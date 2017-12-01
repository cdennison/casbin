// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fileadapter

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"
	"github.com/casbin/casbin/util"
)

// AdapterMock is the file adapter for Casbin.
// It can load policy from file or save policy to file.
type AdapterMock struct {
	filePath   string
	errorValue string
}

// NewAdapterMock is the constructor for AdapterMock.
func NewAdapterMock(filePath string) *AdapterMock {
	a := AdapterMock{}
	a.filePath = filePath
	return &a
}

// LoadPolicy loads all policy rules from the storage.
func (a *AdapterMock) LoadPolicy(model model.Model) error {
	if a.filePath == "" {
		return errors.New("invalid file path, file path cannot be empty")
	}

	err := a.loadPolicyFile(model, persist.LoadPolicyLine)
	return err
}

// SavePolicy saves all policy rules to the storage.
func (a *AdapterMock) SavePolicy(model model.Model) error {
	if a.filePath == "" {
		return errors.New("invalid file path, file path cannot be empty")
	}

	var tmp bytes.Buffer

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			tmp.WriteString(ptype + ", ")
			tmp.WriteString(util.ArrayToString(rule))
			tmp.WriteString("\n")
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			tmp.WriteString(ptype + ", ")
			tmp.WriteString(util.ArrayToString(rule))
			tmp.WriteString("\n")
		}
	}

	err := a.savePolicyFile(strings.TrimRight(tmp.String(), "\n"))
	return err
}

func (a *AdapterMock) loadPolicyFile(model model.Model, handler func(string, model.Model)) error {
	f, err := os.Open(a.filePath)
	if err != nil {
		return err
	}
	buf := bufio.NewReader(f)
	for {
		line, err := buf.ReadString('\n')
		line = strings.TrimSpace(line)
		handler(line, model)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (a *AdapterMock) savePolicyFile(text string) error {
	f, err := os.Create(a.filePath)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	w.WriteString(text)
	w.Flush()
	f.Close()
	return nil
}

func (a *AdapterMock) SetMockErr(errorToSet string) {
	a.errorValue = errorToSet
}

func (a *AdapterMock) GetMockErr() error {
	var returnError error
	if a.errorValue != "" {
		returnError = errors.New(a.errorValue)
	}
	return returnError
}

// AddPolicy adds a policy rule to the storage.
func (a *AdapterMock) AddPolicy(sec string, ptype string, rule []string) error {
	return a.GetMockErr()
}

// RemovePolicy removes a policy rule from the storage.
func (a *AdapterMock) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.GetMockErr()
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *AdapterMock) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.GetMockErr()
}
