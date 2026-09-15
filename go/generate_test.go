//go:build codegen

package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Generation is development-only: PYOSV_SCHEMA=/path go test -tags codegen -run TestGenerateSchema.
func TestGenerateSchema(t *testing.T) {
	path := os.Getenv("PYOSV_SCHEMA")
	if path == "" {
		t.Skip("schema generation not requested")
	}
	generateSchema(t, path)
}

// Development tooling, excluded from the behavioral test suite by the build tag.
func generateSchema(t *testing.T, path string) {
	t.Helper()
	definitions := map[string]any{}
	var messageSchema func(protoreflect.MessageDescriptor) map[string]any
	messageSchema = func(message protoreflect.MessageDescriptor) map[string]any {
		switch message.FullName() {
		case "google.protobuf.Timestamp":
			// Preserve nanoseconds rather than coercing into Python datetime.
			return map[string]any{"type": "string"}
		case "google.protobuf.Struct":
			return map[string]any{"type": "object", "additionalProperties": true}
		}
		name := string(message.Name())
		if name == "Vulnerability" {
			name = "Advisory"
		}
		if name == "Package" {
			name = "AffectedPackage"
		}
		ref := map[string]any{"$ref": "#/$defs/" + name}
		if _, exists := definitions[name]; exists {
			return ref
		}
		properties := map[string]any{}
		definitions[name] = map[string]any{"type": "object", "properties": properties}
		fields := message.Fields()
		for i := range fields.Len() {
			field := fields.Get(i)
			var schema map[string]any
			switch field.Kind() {
			case protoreflect.MessageKind:
				schema = messageSchema(field.Message())
			case protoreflect.EnumKind:
				// ProtoJSON uses enum names, not the integer Go representation.
				schema = map[string]any{"type": "string"}
			case protoreflect.StringKind:
				schema = map[string]any{"type": "string"}
			default:
				t.Fatalf("add ProtoJSON schema mapping for %s (%s)", field.FullName(), field.Kind())
			}
			if field.IsList() {
				schema = map[string]any{"type": "array", "items": schema}
			}
			properties[field.JSONName()] = schema
		}
		return ref
	}
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: true,
		Namer: func(typ reflect.Type) string {
			switch typ.Name() {
			case "response":
				return "NativeResponse"
			case "VulnerabilityResults":
				return "ScanData"
			case "PackageVulns":
				return "Package"
			}
			name := typ.Name()
			if name == "" {
				return ""
			}
			return strings.ToUpper(name[:1]) + name[1:]
		},
		Mapper: func(typ reflect.Type) *jsonschema.Schema {
			if typ == reflect.TypeFor[osvschema.Vulnerability]() {
				messageSchema((&osvschema.Vulnerability{}).ProtoReflect().Descriptor())
				return &jsonschema.Schema{Ref: "#/$defs/Advisory"}
			}
			return nil
		},
	}
	encoded, err := json.Marshal(reflector.Reflect(response{}))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatal(err)
	}
	for name, definition := range definitions {
		schema["$defs"].(map[string]any)[name] = definition
	}
	// Unlike reflection's default, encoding/json permits null Go pointer fields.
	seen := map[reflect.Type]bool{}
	var pointers func(reflect.Type)
	pointers = func(typ reflect.Type) {
		if typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
			pointers(typ.Elem())
			return
		}
		if typ.Kind() != reflect.Struct || seen[typ] || typ == reflect.TypeFor[osvschema.Vulnerability]() {
			return
		}
		seen[typ] = true
		definition, ok := schema["$defs"].(map[string]any)[reflector.Namer(typ)].(map[string]any)
		if !ok {
			return
		}
		properties := definition["properties"].(map[string]any)
		for i := range typ.NumField() {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if !field.IsExported() || name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			if field.Type.Kind() == reflect.Pointer {
				properties[name] = map[string]any{"anyOf": []any{properties[name], map[string]any{"type": "null"}}}
			}
			pointers(field.Type)
		}
	}
	pointers(reflect.TypeFor[response]())
	// encoding/json also emits null for nil Go slices, including nested slices.
	var nullableSlices func(any)
	nullableSlices = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for _, child := range value {
				nullableSlices(child)
			}
			if value["type"] == "array" {
				array := map[string]any{}
				for key, child := range value {
					array[key] = child
					delete(value, key)
				}
				value["anyOf"] = []any{array, map[string]any{"type": "null"}}
			}
		case []any:
			for _, child := range value {
				nullableSlices(child)
			}
		}
	}
	nullableSlices(schema)
	encoded, err = json.MarshalIndent(schema, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
