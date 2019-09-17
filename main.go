package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin"
)

type Cluster struct {
	Name   string
	Owners []string
}

func createEnforcer() *casbin.Enforcer {
	e, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatal(err)
	}

	e.AddFunction("owns", func(args ...interface{}) (interface{}, error) {
		sub := args[0]
		obj := args[1]

		subName, ok := sub.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected type")
		}
		cluster, ok := obj.(*Cluster)
		if !ok {
			return nil, fmt.Errorf("unexpected type")
		}

		for _, o := range cluster.Owners {
			if subName == o {
				return true, nil
			}
		}
		return false, nil
	})
	return e
}

func main() {
	e := createEnforcer()
	sub := "alice"                                           // the user that wants to access a resource.
	obj := &Cluster{Name: "cluster1", Owners: []string{sub}} // the resource that is going to be accessed.
	act := "write"                                           // the operation that the user performs on the resource.

	r, err := e.Enforce(sub, obj, act)
	if err != nil {
		log.Fatal(err)
	}
	if r == true {
		// permit alice to read data1
		log.Printf("Allow")
	} else {
		// deny the request, show an error
		log.Printf("Deny")
	}
}
