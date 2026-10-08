package dkim2

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ErrUnrecoverable reports that the previous body cannot be reconstructed *by
// design*: §12.1.1's "null Recipe", a hop declaring that it cannot be put
// back (see Recipe.BodyNull). Distinct from every other Undo failure, which
// means the reconstruction itself went wrong — DSN propagation answers the
// first by returning the header fields alone and must not answer the second
// that way. Test with errors.Is.
var ErrUnrecoverable = errors.New("previous body declared unrecoverable (null Recipe)")

// Undo reconstructs a message to a previous Message-Instance version by
// applying header and body Recipes backward. targetVersion=-1 means
// highestVersion-1. targetVersion=0 reconstructs the original pre-signing state.
//
// Returns an error wrapping ErrUnrecoverable when a Recipe on the way down
// declares the previous body unrecoverable.
func Undo(r io.Reader, w io.Writer, targetVersion int) error {
	return undo(r, w, targetVersion, false)
}

// undo is Undo's body. With walkPastNull set (the verification path), a null
// body Recipe does not stop the walk: from that instance down only the header
// history is rebuilt and checked (spec-06: the previous body cannot be
// recreated, but header Recipes are mandatory and so the header history can).
// The reconstructed body is then meaningless, so nothing is written to w for
// such a walk beyond what the caller discards.
func undo(r io.Reader, w io.Writer, targetVersion int, walkPastNull bool) error {
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
	bodyGone := false // sticky: a null body Recipe was undone above

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
		if recipe.BodyNull {
			if !walkPastNull {
				return fmt.Errorf("v=%d: %w", version, ErrUnrecoverable)
			}
			bodyGone = true
		}
		// A Recipe that breaks the §5 rules against the message it is
		// applied to (parse-time checks cannot know the item counts) is
		// the same PERMERROR parseMI reports for a structurally bad one.
		if recipe.Headers != nil {
			currentContent, err = undoHeaderRecipes(currentContent, recipe.Headers)
			if err != nil {
				return undoRecipeError(version, err)
			}
		}
		if recipe.Body != nil && !bodyGone {
			currentBody, err = undoBodyRecipe(currentBody, recipe.Body)
			if err != nil {
				return undoRecipeError(version, err)
			}
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
		if bodyGone {
			if err := verifyMIHeaderHashes(targetMI.parsed, currentContent); err != nil {
				return fmt.Errorf("hash mismatch after reconstruction (target v=%d, body not checked below a null body Recipe): %w", targetVersion, err)
			}
		} else {
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

// undoRecipeError reports a failure applying Message-Instance m=version's
// Recipe: the self-describing PERMERROR for a malformed Recipe, otherwise
// the error with the version prefixed.
func undoRecipeError(version int, err error) error {
	if errors.Is(err, errMalformedRecipe) {
		return &malformedRecipeError{m: version}
	}
	return fmt.Errorf("v=%d: %w", version, err)
}

// undoHeaderRecipes applies header Recipes to reconstruct the previous header
// state. recipes keys are lowercase field names. The error wraps
// errMalformedRecipe when a step breaks the §5.1 rules against the current
// instances (a "c" range past the last instance, say).
func undoHeaderRecipes(headers []Header, recipes map[string][]RecipeStep) ([]Header, error) {
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
				reconstructed, err := applyHeaderRecipe(byName[n], h.Name, steps)
				if err != nil {
					return nil, fmt.Errorf("header %q: %w", n, err)
				}
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
			reconstructed, err := applyHeaderRecipe(nil, name, steps)
			if err != nil {
				return nil, fmt.Errorf("header %q: %w", name, err)
			}
			result = append(reconstructed, result...)
		}
	}

	return result, nil
}

// applyHeaderRecipe reconstructs previous header instances for one field.
// current holds the current (after) instances in top-to-bottom order.
func applyHeaderRecipe(current []Header, fieldName string, steps []RecipeStep) ([]Header, error) {
	if err := validateRecipeSteps(steps, len(current)); err != nil {
		return nil, err
	}

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
			emitted = append(emitted, bottomUp[start-1:end]...)
			continue
		}
		vals, err := step.literals() // already validated above
		if err != nil {
			return nil, err
		}
		for _, val := range vals {
			emitted = append(emitted, Header{
				Name:  fieldName,
				Value: val,
				Raw:   fieldName + ": " + val + "\r\n",
			})
		}
	}

	// Reverse from bottom-up to top-to-bottom order.
	for i, j := 0, len(emitted)-1; i < j; i, j = i+1, j-1 {
		emitted[i], emitted[j] = emitted[j], emitted[i]
	}
	return emitted, nil
}

// undoBodyRecipe reconstructs the previous body using body Recipe steps.
// Body is in CRLF format; returned value is also CRLF. The error wraps
// errMalformedRecipe when a step breaks the §5.2 rules against the current
// body (a "c" range past the last line, say).
func undoBodyRecipe(body []byte, steps []RecipeStep) ([]byte, error) {
	lines := splitLines(body)
	if err := validateRecipeSteps(steps, len(lines)); err != nil {
		return nil, fmt.Errorf("body: %w", err)
	}

	var result []string
	for _, step := range steps {
		if step.Copy != nil {
			start, end := step.Copy[0], step.Copy[1]
			result = append(result, lines[start-1:end]...)
			continue
		}
		vals, err := step.literals() // already validated above
		if err != nil {
			return nil, fmt.Errorf("body: %w", err)
		}
		result = append(result, vals...)
	}

	if len(result) == 0 {
		return []byte("\r\n"), nil
	}
	return []byte(strings.Join(result, "\r\n") + "\r\n"), nil
}
