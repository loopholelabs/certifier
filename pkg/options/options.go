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

// Package options contains the options (and default values) used to configure
// DNS and Certificate management
package options

import (
	"github.com/loopholelabs/certifier/internal/memory"
	"github.com/loopholelabs/certifier/pkg/storage"
	"github.com/loopholelabs/logging"
	"github.com/rs/zerolog"
	"io/ioutil"
)

// Option is used to generate options internally
type Option func(opts *Options)

// DefaultLogger is the default Logger
var DefaultLogger logging.Logger

// DefaultStorage is the default Storage
var DefaultStorage storage.Storage

// DefaultTrustedNameServers is the default TrustedNameServers
var DefaultTrustedNameServers = []string{
	"8.8.8.8:53",
	"8.8.4.4:53",
	"1.1.1.1:53",
	"1.0.0.1:53",
}

// init initializes the DefaultLogger and sets up the DefaultStorage
func init() {
	l := zerolog.New(ioutil.Discard)
	DefaultLogger = logging.ConvertZerolog(&l)
	DefaultStorage = memory.New()
}

// Options is used to provide configuration options.
//
// Default Values:
//	options := Options {
//		Logger: DefaultLogger,
//      Storage: DefaultStorage,
//	    TrustedNameServers: DefaultTrustedNameServers,
//	}
type Options struct {
	Logger             logging.Logger
	Storage            storage.Storage
	TrustedNameServers []string
}

// LoadOptions takes a variadic number of Option variables and returns a *Options struct that contains default
// sanitized values.
func LoadOptions(options ...Option) *Options {
	opts := new(Options)
	for _, option := range options {
		option(opts)
	}

	if opts.Logger == nil {
		opts.Logger = DefaultLogger
	}

	if opts.Storage == nil {
		opts.Storage = DefaultStorage
	}

	if opts.TrustedNameServers == nil {
		opts.TrustedNameServers = DefaultTrustedNameServers
	}

	return opts
}

// WithOptions allows users to pass in an Options struct
func WithOptions(options Options) Option {
	return func(opts *Options) {
		*opts = options
	}
}

// WithLogger sets the logger
func WithLogger(logger logging.Logger) Option {
	return func(opts *Options) {
		opts.Logger = logger
	}
}

// WithStorage sets the storage
func WithStorage(storage storage.Storage) Option {
	return func(opts *Options) {
		opts.Storage = storage
	}
}

// WithTrustedNameservers sets the TrustedNameservers
func WithTrustedNameservers(trustedNameservers []string) Option {
	return func(opts *Options) {
		opts.TrustedNameServers = trustedNameservers
	}
}
