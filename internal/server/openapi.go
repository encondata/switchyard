package server

import (
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// handleOpenAPI serves an OpenAPI 3.1 description of the API, generated
// from the operations list, so it always matches what's routed. It's public:
// it describes the API but grants nothing.
func (s *srv) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.openAPI())
}

// obj is a JSON object, for building the document.
type obj = map[string]any

var pathParam = regexp.MustCompile(`\{([a-z]+)\}`)

func (s *srv) openAPI() map[string]any {
	schemas := map[string]any{
		"Error": obj{
			"type": "object",
			"properties": obj{
				"error":   obj{"type": "string", "description": "Machine-readable code, e.g. missing_permission"},
				"message": obj{"type": "string", "description": "What went wrong, in plain words"},
				"fields":  obj{"type": "object", "additionalProperties": obj{"type": "string"}, "description": "Per-field problems, for validation errors"},
			},
			"required": []string{"error", "message"},
		},
	}
	errResp := func(desc string) obj {
		return obj{"description": desc, "content": obj{"application/json": obj{"schema": obj{"$ref": "#/components/schemas/Error"}}}}
	}
	paths := map[string]obj{}
	for _, rt := range s.routes() {
		op := rt.Op
		params := []obj{}
		for _, m := range pathParam.FindAllStringSubmatch(op.Path, -1) {
			typ := "string"
			if m[1] == "id" || m[1] == "n" {
				typ = "integer"
			}
			params = append(params, obj{"name": m[1], "in": "path", "required": true, "schema": obj{"type": typ}})
		}
		for _, q := range op.Query {
			params = append(params, obj{"name": q.Name, "in": "query", "description": q.Description, "schema": obj{"type": "string"}})
		}
		desc := "Session role: " + roleName(op.Role) + "."
		if op.Keyable {
			desc += " API keys need the `" + op.ID + "` permission."
		} else if op.Role != rolePublic {
			desc += " Not available to API keys."
		}
		ok := obj{"description": "Done"}
		if rt.resp != nil {
			ok["content"] = obj{"application/json": obj{"schema": schemaOf(reflect.TypeOf(rt.resp), schemas)}}
		}
		o := obj{
			"operationId": op.ID,
			"summary":     op.Summary,
			"description": desc,
			"tags":        []string{op.Area},
			"parameters":  params,
			"responses": obj{
				"2XX": ok,
				"400": errResp("The request isn't valid; see message and fields"),
				"401": errResp("Not signed in, or the API key isn't valid"),
				"403": errResp("Signed in, but not allowed (role or key permission)"),
				"404": errResp("Not found"),
			},
			"x-keyable": op.Keyable,
			"x-writes":  op.Write,
		}
		switch {
		case op.Role == rolePublic:
			o["security"] = []obj{}
		case op.Keyable:
			o["security"] = []obj{{"apiKey": []string{}}, {"session": []string{}}}
		default:
			o["security"] = []obj{{"session": []string{}}}
		}
		if rt.body != nil {
			o["requestBody"] = obj{"required": true, "content": obj{"application/json": obj{"schema": schemaOf(reflect.TypeOf(rt.body), schemas)}}}
		}
		if paths[op.Path] == nil {
			paths[op.Path] = obj{}
		}
		paths[op.Path][strings.ToLower(op.Method)] = o
	}
	tags := []obj{}
	for _, a := range areas {
		tags = append(tags, obj{"name": a})
	}
	return map[string]any{
		"openapi": "3.1.0",
		"info": obj{
			"title":   "Switchyard API",
			"version": s.version,
			"description": "Manage Switchyard (Caddy reverse proxy) from other programs. " +
				"Authenticate with an API key made by an admin on the API keys page: send it as " +
				"`Authorization: Bearer sy_...` (or `X-API-Key: sy_...`). Each key may call only the " +
				"operations it was given; the permission for each operation is its operationId. " +
				"Changes to hosts, folders, access and DNS are staged: call config.apply " +
				"(POST /api/config/apply) to send them to Caddy.",
		},
		"servers": []obj{{"url": "/"}},
		"tags":    tags,
		"paths":   paths,
		"components": obj{
			"schemas": schemas,
			"securitySchemes": obj{
				"apiKey":  obj{"type": "http", "scheme": "bearer", "description": "An API key (sy_...)"},
				"session": obj{"type": "apiKey", "in": "cookie", "name": sessionCookie, "description": "The web UI's session"},
			},
		},
	}
}

func roleName(r string) string {
	switch r {
	case rolePublic:
		return "none (public)"
	case rolePending:
		return "any signed-in user"
	case roleViewer:
		return "viewer or above"
	case roleEditor:
		return "editor or admin"
	}
	return "admin"
}

var timeType = reflect.TypeOf(time.Time{})

// schemaOf describes a Go type as JSON Schema. Named structs go into
// schemas and are referenced; the JSON field names come from the tags,
// and embedded structs are flattened the way encoding/json does.
func schemaOf(t reflect.Type, schemas map[string]any) obj {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == timeType:
		return obj{"type": "string", "format": "date-time"}
	case t.Kind() == reflect.Bool:
		return obj{"type": "boolean"}
	case t.Kind() >= reflect.Int && t.Kind() <= reflect.Uint64:
		return obj{"type": "integer"}
	case t.Kind() == reflect.Float32 || t.Kind() == reflect.Float64:
		return obj{"type": "number"}
	case t.Kind() == reflect.String:
		return obj{"type": "string"}
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8:
		return obj{"type": "string", "contentEncoding": "base64"}
	case t.Kind() == reflect.Slice || t.Kind() == reflect.Array:
		return obj{"type": "array", "items": schemaOf(t.Elem(), schemas)}
	case t.Kind() == reflect.Map:
		return obj{"type": "object", "additionalProperties": schemaOf(t.Elem(), schemas)}
	case t.Kind() == reflect.Struct:
		name := schemaName(t)
		if name == "" {
			return structSchema(t, schemas)
		}
		if _, done := schemas[name]; !done {
			schemas[name] = obj{} // placeholder, for self-reference
			schemas[name] = structSchema(t, schemas)
		}
		return obj{"$ref": "#/components/schemas/" + name}
	}
	return obj{}
}

func schemaName(t reflect.Type) string {
	n := t.Name()
	if n == "" {
		return ""
	}
	r := []rune(n)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func structSchema(t reflect.Type, schemas map[string]any) obj {
	props := obj{}
	var collect func(reflect.Type)
	collect = func(t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if name == "-" {
				continue
			}
			if f.Anonymous && name == "" {
				ft := f.Type
				for ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}
				if ft.Kind() == reflect.Struct {
					collect(ft)
					continue
				}
			}
			if !f.IsExported() {
				continue
			}
			if name == "" {
				name = f.Name
			}
			props[name] = schemaOf(f.Type, schemas)
		}
	}
	collect(t)
	return obj{"type": "object", "properties": props}
}
