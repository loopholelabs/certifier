/*
	Copyright 2022 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package main

import (
	"flag"
	"github.com/loopholelabs/certifier"
	"github.com/loopholelabs/certifier/pkg/storage/memory"
	"github.com/loopholelabs/logging"
)

var (
	listen string
	root   string
)

func main() {
	logger := logging.NewConsoleLogger()
	logger.SetLevel(logging.DebugLevel)

	storage := memory.New()

	flag.StringVar(&listen, "listen", "", "set the listen address for certifier")
	flag.StringVar(&root, "root", "", "set the root domain for certifier")
	flag.Parse()

	c := certifier.New(root, certifier.WithLogger(logger), certifier.WithStorage(storage))

	if err := c.Start(listen); err != nil {
		panic(err)
	}
}
