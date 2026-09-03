package graphql

import (
	"fmt"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
)

// maxQueryDepth and maxQueryAliases bound query complexity so a hostile client
// cannot exhaust server resources with deeply nested selection sets or a large
// number of aliased fields requesting the same expensive resolver repeatedly
// (alias-based amplification). Checked before execution, ahead of the 1 MiB
// body size cap already enforced in handleGraphQLQuery.
const (
	maxQueryDepth   = 15
	maxQueryAliases = 50
)

// checkQueryComplexity parses query and rejects it if the selection-set depth
// or total alias count exceeds the configured limits. A parse failure here is
// not itself an error — gql.Do will re-parse and report the syntax error with
// proper GraphQL error formatting, so this returns nil and lets execution
// surface it.
func checkQueryComplexity(query string) error {
	if query == "" {
		return nil
	}
	doc, err := parser.Parse(parser.ParseParams{Source: query})
	if err != nil {
		return nil
	}

	fragments := make(map[string]*ast.FragmentDefinition)
	for _, def := range doc.Definitions {
		if fd, ok := def.(*ast.FragmentDefinition); ok && fd.Name != nil {
			fragments[fd.Name.Value] = fd
		}
	}

	aliasCount := 0
	for _, def := range doc.Definitions {
		op, ok := def.(*ast.OperationDefinition)
		if !ok {
			continue
		}
		depth, err := measureSelectionSet(op.SelectionSet, fragments, map[string]bool{}, 1, &aliasCount)
		if err != nil {
			return err
		}
		if depth > maxQueryDepth {
			return fmt.Errorf("graphql: query depth %d exceeds maximum of %d", depth, maxQueryDepth)
		}
	}
	if aliasCount > maxQueryAliases {
		return fmt.Errorf("graphql: query alias count %d exceeds maximum of %d", aliasCount, maxQueryAliases)
	}
	return nil
}

// measureSelectionSet returns the maximum nesting depth reached under ss,
// expanding fragment spreads and inline fragments, and accumulates the total
// number of aliased fields into aliasCount. visiting guards against fragment
// cycles causing unbounded recursion.
func measureSelectionSet(ss *ast.SelectionSet, fragments map[string]*ast.FragmentDefinition, visiting map[string]bool, depth int, aliasCount *int) (int, error) {
	if ss == nil {
		return depth - 1, nil
	}
	if depth > maxQueryDepth {
		// Stop descending once already past the limit — the caller reports the error.
		return depth, nil
	}

	maxDepth := depth - 1
	for _, sel := range ss.Selections {
		switch s := sel.(type) {
		case *ast.Field:
			if s.Alias != nil && s.Alias.Value != "" {
				*aliasCount++
			}
			childDepth := depth
			if s.SelectionSet != nil {
				d, err := measureSelectionSet(s.SelectionSet, fragments, visiting, depth+1, aliasCount)
				if err != nil {
					return 0, err
				}
				childDepth = d
			}
			if childDepth > maxDepth {
				maxDepth = childDepth
			}
		case *ast.InlineFragment:
			d, err := measureSelectionSet(s.SelectionSet, fragments, visiting, depth, aliasCount)
			if err != nil {
				return 0, err
			}
			if d > maxDepth {
				maxDepth = d
			}
		case *ast.FragmentSpread:
			if s.Name == nil {
				continue
			}
			name := s.Name.Value
			if visiting[name] {
				return 0, fmt.Errorf("graphql: fragment cycle detected in %q", name)
			}
			fd, ok := fragments[name]
			if !ok || fd.SelectionSet == nil {
				continue
			}
			visiting[name] = true
			d, err := measureSelectionSet(fd.SelectionSet, fragments, visiting, depth, aliasCount)
			delete(visiting, name)
			if err != nil {
				return 0, err
			}
			if d > maxDepth {
				maxDepth = d
			}
		}
		if maxDepth > maxQueryDepth {
			return maxDepth, nil
		}
	}
	return maxDepth, nil
}
