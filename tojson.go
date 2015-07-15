package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"strings"
)

var ThreatSpecPattern = regexp.MustCompile(`ThreatSpec (?P<Model>.+?) for (?P<Function>.+?)$`)
var MitigationPattern = regexp.MustCompile(`Mitigates (?P<Component>.+?) against (?P<Threat>.+?) with (?P<Mitigation>.+?)\s*(?:\((?P<Ref>.*?)\))?$`)
var ExposurePattern = regexp.MustCompile(`Exposes (?P<Component>.+?) to (?P<Threat>.+?) with (?P<Exposure>.+?)\s*(?:\((?P<Ref>.*?)\))?`)
var DoesPattern = regexp.MustCompile(`Does (?P<Action>.+?) for (?P<Component>.+?)\s*(?:\((?P<Ref>.*?)\))?$`)
var res = []*regexp.Regexp{ThreatSpecPattern, MitigationPattern, ExposurePattern, DoesPattern}

type Function struct {
	Name       string `json:"name"`
	Package    string `json:"package"`
	Begin      int    `json:"begin"`
	End        int    `json:"end"`
	Filepath   string `json:"filepath"`
	Mitigation string `json:"mitigation,omitempty"`
	Model      string `json:"model,omitempty"`
	Threat     string `json:"threat,omitempty"`
	Exposure   string `json:"exposure,omitempty"`
	Component  string `json:"component,omitempty"`
	Action     string `json:"action,omitempty"`
	Function   string `json:"function,omitempty"` // for threatspec compliance
	Ref        string `json:"ref,omitempty"`
}

func (f *Function) getTSpec(cs []*ast.CommentGroup) {
	for _, lines := range cs { // each comment group
		for _, line := range strings.Split(lines.Text(), "\n") { // each comment line
			for _, re := range res {
				m := re.FindStringSubmatch(line)
				if len(m) > 1 {
					for i, field := range re.SubexpNames() {
						if i == 0 {
							continue
						}
						reflect.ValueOf(f).Elem().FieldByName(field).SetString(m[i])
					}
				}
			}
		}
	}
}

func processFile(filename string) []Function {
	var res []Function
	fset := token.NewFileSet() // positions are relative to fset
	f, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	cmap := ast.NewCommentMap(fset, f, f.Comments)
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			fun := Function{Begin: fset.Position(x.Pos()).Line,
				Package:  f.Name.String(),
				Name:     x.Name.String(),
				End:      fset.Position(x.End()).Line,
				Filepath: fset.Position(x.Pos()).Filename}

			fun.getTSpec(cmap[n])
			res = append(res, fun)
		}
		return true
	})
	return res
}

func main() {
	enc := json.NewEncoder(os.Stdout)

	var funcs []Function
	for _, filename := range os.Args[1:] {
		funcs = append(funcs, processFile(filename)...)
	}

	err := enc.Encode(&funcs)
	if err != nil {
		panic(err)
	}
}
