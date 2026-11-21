package dkim2

import (
	"bufio"
	"context"
	"io"
	"slices"

	"cloudeng.io/algo/lcs"
)

//XXXX Tests for body diff. Create MessageInstance hashes.

func diffBody(oldBody, newBody io.Reader) *RecipeBodySteps {
	var oldLines, newLines []string

	scanner := bufio.NewScanner(oldBody)
	for scanner.Scan() {
		oldLines = append(oldLines, scanner.Text())
	}

	scanner = bufio.NewScanner(newBody)
	for scanner.Scan() {
		newLines = append(newLines, scanner.Text())
	}

	// Common case is that they're identical
	if slices.Equal(newLines, oldLines) {
		return nil
	}

	edits := lcs.NewMyers(newLines, oldLines).SES()
	var steps RecipeBodySteps
	var currentStep RecipeBodyStep
	for _, edit := range *edits {
		switch edit.Op {
		case lcs.Insert:
			// Inserting new content
			curData, ok := currentStep.(RecipeDataBodyStep)
			if ok {
				curData = append(curData, edit.Val)
				currentStep = curData
				continue
			}
			if currentStep != nil {
				steps = append(steps, currentStep)
			}
			currentStep = RecipeDataBodyStep{edit.Val}
			continue
		case lcs.Identical:
			// Copying content
			curCopy, ok := currentStep.(RecipeCopyBodyStep)
			if ok && curCopy[1] == edit.A {
				curCopy[1] = edit.A + 1
				currentStep = curCopy
				continue
			}
			if currentStep != nil {
				steps = append(steps, currentStep)
			}
			currentStep = RecipeCopyBodyStep{edit.A + 1, edit.A + 1}
			continue
		}
	}
	if currentStep != nil {
		steps = append(steps, currentStep)
	}
	return &steps
}

func diffHeaders(ctx context.Context, oldHeader, newHeader map[string][]string) *RecipeHeaderMap {
	if headersEqual(oldHeader, newHeader) {
		return nil
	}
	res := RecipeHeaderMap{}
	for headerName, oldValues := range oldHeader {
		slices.Reverse(oldValues)
		newValues, ok := newHeader[headerName]
		if !ok {
			// New doesn't have this header, so we need to add them all
			res[headerName] = []RecipeHeaderStep{RecipeDataHeaderStep(oldValues)}
			continue
		}
		slices.Reverse(newValues)
		if slices.Equal(oldValues, newValues) {
			// No change, so we don't need to record any recipe
			continue
		}

		sourceLoc := map[string]int{}
		for i, h := range newValues {
			sourceLoc[h] = i + 1
		}
		// FIXME(steve): If we have multiple identical headers we'll start copying at the latest
		// and our recipe will include more "d" than it needs to.
		var steps []RecipeHeaderStep
		var currentStep RecipeHeaderStep
		var highestSeen int
		for _, nh := range oldValues {
			i, ok := sourceLoc[nh]
			if ok && i > highestSeen {
				// We're copying from an existing header
				curCopy, ok := currentStep.(RecipeCopyHeaderStep)
				if ok && curCopy[1] == i-1 {
					curCopy[1] = i
					currentStep = curCopy
					highestSeen = i
					continue
				}
				if currentStep != nil {
					steps = append(steps, currentStep)
				}
				currentStep = RecipeCopyHeaderStep{i, i}
				highestSeen = i
				continue
			}
			// We're putting new content in this header
			curData, ok := currentStep.(RecipeDataHeaderStep)
			if ok {
				curData = append(curData, nh)
				currentStep = curData
				continue
			}
			if currentStep != nil {
				steps = append(steps, currentStep)
			}
			currentStep = RecipeDataHeaderStep{nh}
		}
		if currentStep != nil {
			steps = append(steps, currentStep)
		}
		res[headerName] = steps
	}

	// Delete all the headers that are in new but not old
	for k := range newHeader {
		if _, ok := oldHeader[k]; !ok {
			// Delete all headers with this name
			res[k] = []RecipeHeaderStep{}
		}
	}
	return &res
}
