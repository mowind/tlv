package tlv

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
)

var (
	errIndefiniteLength = errors.New("intefinite length is not supported")
	errInvalidLength    = errors.New("invalid length")
)

func Unmarshal(b []byte, v interface{}) error {
	return decodeValue(b, v)
}

func decodeValue(b []byte, v interface{}) error {
	value := reflect.ValueOf(v)

	if unmarshaler, ok := value.Interface().(encoding.BinaryUnmarshaler); ok {
		err := unmarshaler.UnmarshalBinary(b)
		return err
	}

	value = reflect.Indirect(value)
	valueType := reflect.TypeOf(value.Interface())
	switch value.Kind() {
	case reflect.Int8:
		tmp := int64(int8(b[0]))
		value.SetInt(tmp)
	case reflect.Int16:
		tmp := int64(int16(binary.BigEndian.Uint16(b)))
		value.SetInt(tmp)
	case reflect.Int32:
		tmp := int64(int32(binary.BigEndian.Uint32(b)))
		value.SetInt(tmp)
	case reflect.Int64:
		tmp := int64(binary.BigEndian.Uint64(b))
		value.SetInt(tmp)
	case reflect.Int:
		tmp := int64(binary.BigEndian.Uint64(b))
		value.SetInt(tmp)
	case reflect.Uint8:
		tmp := uint64(b[0])
		value.SetUint(tmp)
	case reflect.Uint16:
		tmp := uint64(binary.BigEndian.Uint16(b))
		value.SetUint(tmp)
	case reflect.Uint32:
		tmp := uint64(binary.BigEndian.Uint32(b))
		value.SetUint(tmp)
	case reflect.Uint64:
		tmp := binary.BigEndian.Uint64(b)
		value.SetUint(tmp)
	case reflect.Uint:
		tmp := binary.BigEndian.Uint64(b)
		value.SetUint(tmp)
	case reflect.String:
		value.SetString(string(b))
	case reflect.Ptr:
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		if err := decodeValue(b, value.Interface()); err != nil {
			return err
		}
	case reflect.Struct:
		var tlvFragment fragments
		if tlvFragmentTmp, err := parseTLV(b); err != nil {
			return err
		} else {
			tlvFragment = tlvFragmentTmp
		}
		for i := 0; i < value.NumField(); i++ {
			fieldValue := value.Field(i)
			fieldType := valueType.Field(i)

			tag, hasTLV := fieldType.Tag.Lookup("tlv")
			if !hasTLV {
				return errors.New("field " + fieldType.Name + " need tag `tlv`")
			}

			tagHex, err := hex.DecodeString(tag)
			if err != nil {
				return fmt.Errorf("invalid tlv tag \"%s\", need to be decimal number", tag)
			}
			tagVal := int(big.NewInt(0).SetBytes(tagHex).Int64())

			if len(tlvFragment[tagVal]) == 0 {
				continue
			}

			if fieldValue.Kind() == reflect.Ptr && fieldValue.IsNil() {
				fieldValue.Set(reflect.New(fieldValue.Type().Elem()))
			} else if fieldValue.Kind() == reflect.Slice && fieldValue.IsNil() {
				fieldValue.Set(reflect.MakeSlice(fieldValue.Type(), 0, 1))
			}

			for _, buf := range tlvFragment[tagVal] {
				if fieldValue.Kind() != reflect.Ptr {
					fieldValue = fieldValue.Addr()
				}
				err = decodeValue(buf, fieldValue.Interface())
				if err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		if value.IsNil() {
			value.Set(reflect.MakeSlice(value.Type(), 0, 1))
		}
		if valueType.Elem().Kind() == reflect.Uint8 {
			value.SetBytes(b)
		} else if valueType.Elem().Kind() == reflect.Ptr || valueType.Elem().Kind() == reflect.Struct ||
			isNumber(valueType.Elem()) {
			elemValue := reflect.New(valueType.Elem())
			if err := decodeValue(b, elemValue.Interface()); err != nil {
				return err
			}
			value.Set(reflect.Append(value, elemValue.Elem()))
		} else {
			return errors.New("value type `Slice of " + valueType.String() + "` is not support decode")
		}
	}
	return nil
}

func parseTLV(b []byte) (fragments, error) {
	tlvFragment := make(fragments)
	buffer := bytes.NewBuffer(b)

	var tag int
	var length int
	var err error
	for {
		tag, err = parseTag(buffer)
		if err != nil {
			return tlvFragment, err
		}
		length, err = parseLen(buffer)
		if err != nil {
			return tlvFragment, err
		}
		value := make([]byte, length)
		if _, err := buffer.Read(value); err != nil {
			return nil, err
		}
		tlvFragment.Add(int(tag), value)
		if buffer.Len() == 0 {
			break
		}
	}
	return tlvFragment, nil
}

func parseTag(buf *bytes.Buffer) (int, error) {
	b := make([]byte, 1)
	if err := binary.Read(buf, binary.BigEndian, b); err != nil {
		return 0, err
	}

	tag := int(b[0])
	if b[0]&0x1F == 0x1F { //it's a two byte tag
		tag <<= 8

		if err := binary.Read(buf, binary.BigEndian, b); err != nil {
			return 0, err
		}
		tag |= int(b[0])
	}
	return tag, nil
}

func parseLen(buf *bytes.Buffer) (int, error) {
	b := make([]byte, 1)

	if err := binary.Read(buf, binary.BigEndian, b); err != nil {
		return 0, err
	}

	if b[0] == 0x80 {
		return 0, errIndefiniteLength
	}

	if b[0]&0x80 == 0 {
		return int(b[0]), nil
	}

	nb := int(b[0] & 0x7f)
	if nb > 4 {
		return 0, errInvalidLength
	}

	lenb := make([]byte, 4)
	if err := binary.Read(buf, binary.BigEndian, lenb[4-nb:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint32(lenb)), nil
}
