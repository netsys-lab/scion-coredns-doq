package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
)

func Int32ToByteSlice(n int) []byte {
	// second method, convert the int directly to []byte
	// if you know the machine endian
	// for example, LittleEndian

	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.LittleEndian, uint32(n))
	if err != nil {
		fmt.Println(err)
	}

	intByteArray := buff.Bytes()
	fmt.Printf("intByteArray : % x\n", intByteArray)
	fmt.Println("intByteArray type is : ", reflect.TypeOf(intByteArray))

	// verify if 123 translates to 7b correctly
	// byteI := byte(n)
	// fmt.Printf("%v % x (%T)\n", n, byteI, byteI)

	// finally, if you just want to
	// get the ASCII representation.
	// Converting intVar to string first will do the job
	/*
		intByte := []byte(strconv.Itoa(n))
		fmt.Println("intByte is : ", intByte)
		fmt.Println("intByte in string : ", string(intByte))
		fmt.Println("intByte type is : ", reflect.TypeOf(intByte))*/

	return intByteArray
}

func main() {

	f, err := os.Create("dummy.luki.test.home20000.db")

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	var dummy_domain string = "dummy.luki.test.home"
	// the zonefile will have this many entries
	var entries int = 20000

	var a uint8 = 192
	var b uint8 = 0
	var c uint8 = 0
	var d uint8 = 0

	for i := 0; i < entries; i++ {
		d += 1

		if d >= 255 {
			c += 1
			d = 1
		}
		if c >= 255 {
			b += 1
			c = 0
		}
		if b >= 255 {
			a += 1
			b = 0
		}
		//var ip net.IP = Int32ToByteSlice(i)
		var ip net.IP = net.IP{a, b, c, d}
		// var ipStr string = string(ip)
		var line string = fmt.Sprintf("%s.    IN    A    %v\n", dummy_domain, ip)
		_, err2 := f.WriteString(line)

		if err2 != nil {
			log.Fatal(err2)
		}

	}
	fmt.Println("done")
}
