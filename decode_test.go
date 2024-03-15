package tlv

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnmarshal(t *testing.T) {
	testCases := []struct {
		name     string
		instance interface{}
		inputHex string
	}{
		{
			name: "int64",
			instance: struct {
				Value int64 `tlv:"1E"`
			}{Value: 32324},
			inputHex: "1E080000000000007E44",
		},
		{
			name: "int32",
			instance: struct {
				Value int32 `tlv:"2F"`
			}{Value: 32324},
			inputHex: "2F0400007E44",
		},
		{
			name: "int16",
			instance: struct {
				Value int16 `tlv:"20"`
			}{Value: 32324},
			inputHex: "20027E44",
		},
		{
			name: "int8",
			instance: struct {
				Value int8 `tlv:"21"`
			}{Value: 68},
			inputHex: "210144",
		},
		{
			name: "slice of struct",
			instance: struct {
				List []struct {
					Name     []byte `tlv:"14"`
					Sequence uint16 `tlv:"28"`
				} `tlv:"50"`
			}{
				List: []struct {
					Name     []byte `tlv:"14"`
					Sequence uint16 `tlv:"28"`
				}{
					{Name: []byte("Hello"), Sequence: 1},
					{Name: []byte("World"), Sequence: 2},
					{Name: []byte("free5gc"), Sequence: 3},
				},
			},
			inputHex: "500B140548656C6C6F28020001" +
				"500B1405576F726C6428020002" +
				"500D14076672656535676328020003",
		},
		{
			name: "slice of binary",
			instance: struct {
				List []BinaryMarshalTest `tlv:"7B"`
			}{
				List: []BinaryMarshalTest{
					{
						Value: 1100,
					},
					{
						Value: 1200,
					},
					{
						Value: 3244,
					},
				},
			},
			inputHex: "7B04313130307B04313230307B0433323434",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			instanceType := reflect.TypeOf(tc.instance)
			testInstance := reflect.New(instanceType).Interface()

			buf, err := hex.DecodeString(tc.inputHex)
			require.NoError(t, err)
			err = Unmarshal(buf, testInstance)
			require.NoError(t, err)

			// dereference the interface
			testInstance = reflect.ValueOf(testInstance).Elem().Interface()
			require.Equal(t, tc.instance, testInstance)
		})
	}
}
