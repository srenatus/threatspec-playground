package main

import (
	"encoding/csv"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var ThreatSpecPattern = regexp.MustCompile(`ThreatSpec (?P<model>.+?) for (?P<function>.+?)$`)
var MitigationPattern = regexp.MustCompile(`Mitigates (?P<component>.+?) against (?P<threat>.+?) with (?P<mitigation>.+?)\s*(?:\((?P<ref>.*?)\))?$`)
var ExposurePattern = regexp.MustCompile(`Exposes (?P<component>.+?) to (?P<threat>.+?) with (?P<exposure>.+?)\s*(?:\((?P<ref>.*?)\))?`)
var DoesPattern = regexp.MustCompile(`Does (?P<action>.+?) for (?P<component>.+?)\s*(?:\((?P<ref>.*?)\))?$`)

// TODO: account for number of captures (not always == 3)
func iff(b bool, sth []string) []string {
	if b {
		return sth[1:]
	} else {
		return []string{"", "", ""}
	}
}

func getTSpec(cs []*ast.CommentGroup) []string {
	r := []string{}
	var t, m, e, d []string
	var foundt, foundm, founde, foundd = false, false, false, false

	for _, lines := range cs { // each comment group
		for _, line := range strings.Split(lines.Text(), "\n") { // each comment line
			if !foundt {
				t = ThreatSpecPattern.FindStringSubmatch(line)
				foundt = len(t) > 0
			}
			if !foundm {
				m = MitigationPattern.FindStringSubmatch(line)
				foundm = len(m) > 0
			}
			if !founde {
				e = ExposurePattern.FindStringSubmatch(line)
				founde = len(e) > 0
			}
			if !foundd {
				d = DoesPattern.FindStringSubmatch(line)
				foundd = len(d) > 0
			}
		}
	}
	// TODO: validation
	// - are multiple component parts equal?
	// - function in ThreatSpec and in function name equal?
	r = append(r, iff(foundt, t)...)
	r = append(r, iff(foundm, m)...)
	r = append(r, iff(founde, e)...)
	r = append(r, iff(foundd, d)...)
	return r
}

func main() {
	// output csv
	csvfile, err := os.Create("output.csv")
	if err != nil {
		panic(err)
	}
	defer csvfile.Close()

	writer := csv.NewWriter(csvfile)
	writer.Write([]string{"filename", "functionname", "begin", "end", "tsmodel", "tsfunction", "mcomponent", "mthreat", "mmitigation", "mref", "ecomponent", "ethreat", "eexposure", "eref", "daction", "dcomponent", "dref"}) // header

	for _, filename := range os.Args[1:] {
		fset := token.NewFileSet() // positions are relative to fset
		f, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
		if err != nil {
			panic(err)
		}

		// use commentmap, since Doc() comment in ast below is not enough
		cmap := ast.NewCommentMap(fset, f, f.Comments)

		// iterate over function declarations from AST
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				writer.Write(append([]string{fset.Position(x.Pos()).Filename, x.Name.String(), strconv.Itoa(fset.Position(x.Pos()).Line), strconv.Itoa(fset.Position(x.End()).Line)}, getTSpec(cmap[n])...))
			}
			return true
		})

	}

	writer.Flush()
}
