package main

import "github.com/tuckyapps/zero-knowledge-proof/internal/zkdb"

import zeroknowledge "github.com/tuckyapps/zero-knowledge-proof/internal/zero_knowledge"

import "github.com/tuckyapps/zero-knowledge-proof/internal/zktcp"

func main() {
	var db = new(zkdb.MemoryDB)
	err := zeroknowledge.Init(db)
	checkErr(err)

	err = zktcp.Init()
	checkErr(err)

}

func checkErr(err error) {
	if err != nil {
		panic(err.Error())
	}
}
