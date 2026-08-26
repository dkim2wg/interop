package dkim2

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Undo reconstructs a message to a previous Message-Instance version by
// applying header and body Recipes backward. targetVersion=-1 means
// highestVersion-1. targetVersion=0 reconstructs the original pre-signing state.
func Undo(r io.Reader, w io.Writer, targetVersion int) error {
	headers, bodyReader, err := parseHeaders(r)
	if err != nil {
		return fmt.Errorf("parsing headers: %w", err)
	}
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		return fmt.Errorf("reading body: %w", err)
	}

	type miEntry struct {
		version int
		raw     string
		parsed  *MessageInstance
	}
	var miList []miEntry
	var sigRaws []string
	var contentHeaders []Header

	for _, h := range headers {
		switch strings.ToLower(h.Name) {
		case "message-instance":
			mi, err := parseMI(h.Raw)
			if err != nil {
				return fmt.Errorf("parsing MI: %w", err)
			}
			miList = append(miList, miEntry{mi.Version, h.Raw, mi})
		case "dkim2-signature":
			sigRaws = append(sigRaws, h.Raw)
		default:
			contentHeaders = append(contentHeaders, h)
		}
	}

	if len(miList) == 0 {
		return fmt.Errorf("no Message-Instance headers found")
	}

	sort.Slice(miList, func(i, j int) bool {
		return miList[i].version < miList[j].version
	})

	highestVersion := miList[len(miList)-1].version

	if targetVersion == -1 {
		targetVersion = highestVersion - 1
	}
	if targetVersion < 0 {
		return fmt.Errorf("target version %d is invalid", targetVersion)
	}
	if targetVersion >= highestVersion {
		return fmt.Errorf("target version %d >= highest version %d, nothing to undo",
			targetVersion, highestVersion)
	}

	currentContent := make([]Header, len(contentHeaders))
	copy(currentContent, contentHeaders)
	currentBody := body

	for version := highestVersion; version > targetVersion; version-- {
		var entry *miEntry
		for i := range miList {
			if miList[i].version == version {
				entry = &miList[i]
				break
			}
		}
		if entry == nil {
			return fmt.Errorf("Message-Instance v=%d not found", version)
		}

		if entry.parsed.Recipe == nil {
			continue
		}

		recipe := entry.parsed.Recipe
		if recipe.Headers != nil {
			currentContent = undoHeaderRecipes(currentContent, recipe.Headers)
		}
		if recipe.Body != nil {
			currentBody = undoBodyRecipe(currentBody, recipe.Body)
		}
	}

	// Verify reconstructed state against target MI hashes.
	// targetVersion=0 means pre-signing; no MI v=0 exists to verify against.
	if targetVersion >= 1 {
		var targetMI *miEntry
		for i := range miList {
			if miList[i].version == targetVersion {
				targetMI = &miList[i]
				break
			}
		}
		if targetMI == nil {
			return fmt.Errorf("Message-Instance v=%d not found for verification", targetVersion)
		}
		{
			if err := verifyMIHashes(targetMI.parsed, currentContent, currentBody); err != nil {
				return fmt.Errorf("hash mismatch after reconstruction (target v=%d): %w", targetVersion, err)
			}
		}
	}

	// Write output: sigs with m= <= target, MIs with v= <= target,
	// reconstructed content headers, blank line, body.
	for _, raw := range sigRaws {
		sig, err := parseSig(raw)
		if err != nil {
			return fmt.Errorf("parsing DKIM2-Signature for output: %w", err)
		}
		if sig.MIVersion > targetVersion {
			continue
		}
		if _, err := io.WriteString(w, raw); err != nil {
			return err
		}
	}
	for _, mi := range miList {
		if mi.version > targetVersion {
			continue
		}
		if _, err := io.WriteString(w, mi.raw); err != nil {
			return err
		}
	}
	for _, h := range currentContent {
		if _, err := io.WriteString(w, h.Raw); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "\r\n"); err != nil {
		return err
	}
	if _, err := w.Write(currentBody); err != nil {
		return err
	}

	return nil
}

// undoHeaderRecipes applies header Recipes to reconstruct the previous header
// state. recipes keys are lowercase field names.
func undoHeaderRecipes(headers []Header, recipes map[string][]RecipeStep) []Header {
	lcRecipes := make(map[string][]RecipeStep, len(recipes))
	for k, v := range recipes {
		lcRecipes[lowerName(k)] = v
	}

	byName := make(map[string][]Header)
	for _, h := range headers {
		n := lowerName(h.Name)
		byName[n] = append(byName[n], h)
	}

	processed := make(map[string]bool)
	var result []Header

	for _, h := range headers {
		n := lowerName(h.Name)
		if steps, ok := lcRecipes[n]; ok {
			if !processed[n] {
				processed[n] = true
				reconstructed := applyHeaderRecipe(byName[n], h.Name, steps)
				result = append(result, reconstructed...)
			}
		} else {
			result = append(result, h)
		}
	}

	// Fields present in recipes but not in current headers were added by the
	// intermediary; prepend their reconstructed (pre-addition) instances.
	for name, steps := range lcRecipes {
		if !processed[name] && len(steps) > 0 {
			processed[name] = true
			reconstructed := applyHeaderRecipe(nil, name, steps)
			result = append(reconstructed, result...)
		}
	}

	return result
}

// applyHeaderRecipe reconstructs previous header instances for one field.
// current holds the current (after) instances in top-to-bottom order.
func applyHeaderRecipe(current []Header, fieldName string, steps []RecipeStep) []Header {
	// Instances are indexed bottom-up: instance 1 = last occurrence.
	bottomUp := make([]Header, len(current))
	copy(bottomUp, current)
	for i, j := 0, len(bottomUp)-1; i < j; i, j = i+1, j-1 {
		bottomUp[i], bottomUp[j] = bottomUp[j], bottomUp[i]
	}

	// Steps were built in before-bottom-up order; emitted list is also bottom-up.
	var emitted []Header
	for _, step := range steps {
		if step.Copy != nil {
			start, end := step.Copy[0], step.Copy[1]
			for i := start; i <= end; i++ {
				if idx := i - 1; idx >= 0 && idx < len(bottomUp) {
					emitted = append(emitted, bottomUp[idx])
				}
			}
		} else {
			for _, val := range step.Data {
				emitted = append(emitted, Header{
					Name:  fieldName,
					Value: val,
					Raw:   fieldName + ": " + val + "\r\n",
				})
			}
		}
	}

	// Reverse from bottom-up to top-to-bottom order.
	for i, j := 0, len(emitted)-1; i < j; i, j = i+1, j-1 {
		emitted[i], emitted[j] = emitted[j], emitted[i]
	}
	return emitted
}

// undoBodyRecipe reconstructs the previous body using body Recipe steps.
// Body is in CRLF format; returned value is also CRLF.
func undoBodyRecipe(body []byte, steps []RecipeStep) []byte {
	lines := splitLines(body)

	var result []string
	for _, step := range steps {
		if step.Copy != nil {
			start, end := step.Copy[0], step.Copy[1]
			for i := start; i <= end; i++ {
				if idx := i - 1; idx >= 0 && idx < len(lines) {
					result = append(result, lines[idx])
				}
			}
		} else {
			result = append(result, step.Data...)
		}
	}

	if len(result) == 0 {
		return []byte("\r\n")
	}
	return []byte(strings.Join(result, "\r\n") + "\r\n")
}
