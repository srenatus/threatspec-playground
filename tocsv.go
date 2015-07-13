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
var res = []*regexp.Regexp{ThreatSpecPattern, MitigationPattern, ExposurePattern, DoesPattern}

type Measurement struct {
	Variable string
	Value    string
}

func getTSpec(name string, cs []*ast.CommentGroup, out func(Measurement)) {
	for _, lines := range cs { // each comment group
		for _, line := range strings.Split(lines.Text(), "\n") { // each comment line
			for _, re := range res {
				m := re.FindStringSubmatch(line)
				if len(m) > 1 {
					for i, v := range re.SubexpNames() {
						if i == 0 {
							continue
						}
						out(Measurement{name + "/" + v, m[i]})
					}
				}
			}
		}
	}
}

func processFile(filename string, out func(Measurement)) {
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
			name := f.Name.String() + "/" + x.Name.String()
			out(Measurement{name + "/begin", strconv.Itoa(fset.Position(x.Pos()).Line)})
			out(Measurement{name + "/end", strconv.Itoa(fset.Position(x.End()).Line)})
			out(Measurement{name + "/filename", fset.Position(x.Pos()).Filename})

			getTSpec(name, cmap[n], out)
		}
		return true
	})
}

func main() {
	// output csv
	csvfile, err := os.Create("output.csv")
	if err != nil {
		panic(err)
	}
	defer csvfile.Close()

	writer := csv.NewWriter(csvfile)
	writer.Write([]string{"variable", "value"})

	for _, filename := range os.Args[1:] {
		processFile(filename, func(m Measurement) {
			writer.Write([]string{m.Variable, m.Value})
		})
	}

	writer.Flush()
}
