package storagetest_test

import (
	"testing"

	"github.com/kyosu-1/grantor"
	"github.com/kyosu-1/grantor/memory"
	"github.com/kyosu-1/grantor/storagetest"
)

// Run the suite from a test in the package that implements the storage.
func ExampleRun() {
	_ = func(t *testing.T) {
		storagetest.Run(t, func(t *testing.T) grantor.Storage {
			return memory.New() // replace with a new, empty instance of your storage
		})
	}
}
