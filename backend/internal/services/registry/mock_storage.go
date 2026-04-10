// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package registry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/michielvha/stackweaver/core/storage"
)

// MockStorage is an in-memory storage implementation for testing.
// Implements storage.Client.
type MockStorage struct {
	objects map[string][]byte
}

// NewMockStorage creates a new mock storage
func NewMockStorage() *MockStorage {
	return &MockStorage{
		objects: make(map[string][]byte),
	}
}

var ErrObjectNotFound = errors.New("object not found")

func (m *MockStorage) Put(_ context.Context, key string, data []byte) error {
	m.objects[key] = data
	return nil
}

func (m *MockStorage) Get(_ context.Context, key string) ([]byte, error) {
	data, ok := m.objects[key]
	if !ok {
		return nil, ErrObjectNotFound
	}
	return data, nil
}

func (m *MockStorage) Delete(_ context.Context, key string) error {
	delete(m.objects, key)
	return nil
}

func (m *MockStorage) PutStream(_ context.Context, key string, reader io.Reader, size int64) error {
	var data []byte
	var err error
	if size >= 0 {
		data = make([]byte, size)
		_, err = io.ReadFull(reader, data)
	} else {
		data, err = io.ReadAll(reader)
	}
	if err != nil {
		return err
	}
	m.objects[key] = data
	return nil
}

func (m *MockStorage) GetStream(_ context.Context, key string) (io.ReadCloser, error) {
	data, ok := m.objects[key]
	if !ok {
		return nil, ErrObjectNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *MockStorage) List(_ context.Context, prefix string) ([]storage.ObjectInfo, error) {
	var results []storage.ObjectInfo
	for key, data := range m.objects {
		if strings.HasPrefix(key, prefix) {
			results = append(results, storage.ObjectInfo{
				Key:  key,
				Size: int64(len(data)),
			})
		}
	}
	return results, nil
}

func (m *MockStorage) PresignGet(_ context.Context, key string, _ time.Duration) (string, error) {
	if _, ok := m.objects[key]; !ok {
		return "", ErrObjectNotFound
	}
	return "http://mock-storage.example.com/" + key, nil
}

func (m *MockStorage) Ping(_ context.Context) error {
	return nil
}
