package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/apimgr/ipgaze/src/swagger"
)

type routeResponseRecorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newRouteResponseRecorder() *routeResponseRecorder {
	return &routeResponseRecorder{header: make(http.Header)}
}

func (w *routeResponseRecorder) Header() http.Header            { return w.header }
func (w *routeResponseRecorder) WriteHeader(status int)         { w.status = status }
func (w *routeResponseRecorder) Write(body []byte) (int, error) { return w.body.Write(body) }

func withRouteTextSerializer(route swagger.Route, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if route.Binary != "" || apiResponseFormat(r) != "text" {
			next(w, r)
			return
		}
		captured := newRouteResponseRecorder()
		next(captured, r)
		if !strings.HasPrefix(strings.ToLower(captured.header.Get("Content-Type")), "application/json") {
			copyRouteResponse(w, captured)
			return
		}
		var envelope struct {
			OK      bool            `json:"ok"`
			Data    json.RawMessage `json:"data"`
			Error   string          `json:"error"`
			Message string          `json:"message"`
		}
		if err := json.Unmarshal(captured.body.Bytes(), &envelope); err != nil {
			copyRouteResponse(w, captured)
			return
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(captured.body.Bytes(), &fields) == nil {
			if _, wrapped := fields["ok"]; !wrapped {
				if route.Primary == "" {
					// Health, GraphQL and the OpenAPI document have explicit bare-JSON
					// response contracts; they do not use the API text envelope.
					copyRouteResponse(w, captured)
					return
				}
				envelope.OK = true
				envelope.Data = captured.body.Bytes()
			}
		}
		for key, values := range captured.header {
			if strings.EqualFold(key, "Content-Type") {
				continue
			}
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		status := captured.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if !envelope.OK {
			_, _ = fmt.Fprintf(w, "ERROR: %s: %s\n", envelope.Error, envelope.Message)
			return
		}
		data := routeTextValue(route, envelope.Data)
		if route.Primary != "" {
			if value, ok := primaryRouteValue(route, data); ok {
				_, _ = fmt.Fprintln(w, value)
				return
			}
		}
		message := envelope.Message
		if message == "" {
			message = route.Message
		}
		writeRouteTextData(w, data, message)
	}
}

func copyRouteResponse(w http.ResponseWriter, captured *routeResponseRecorder) {
	for key, values := range captured.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	if captured.status != 0 {
		w.WriteHeader(captured.status)
	}
	_, _ = w.Write(captured.body.Bytes())
}

func routeTextValue(route swagger.Route, raw json.RawMessage) any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if route.Response != nil {
		typeOfResponse := reflect.TypeOf(route.Response)
		if typeOfResponse.Kind() == reflect.Ptr {
			typeOfResponse = typeOfResponse.Elem()
		}
		if typeOfResponse.Kind() == reflect.Struct {
			value := reflect.New(typeOfResponse)
			if json.Unmarshal(raw, value.Interface()) == nil {
				return value.Elem().Interface()
			}
		}
	}
	var value any
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	return nil
}

func primaryRouteValue(route swagger.Route, data any) (any, bool) {
	value := reflect.ValueOf(data)
	if !value.IsValid() {
		return nil, false
	}
	for value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, false
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Struct:
		typeOf := value.Type()
		for i := 0; i < value.NumField(); i++ {
			field := typeOf.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == route.Primary {
				return value.Field(i).Interface(), true
			}
		}
	case reflect.Map:
		key := reflect.ValueOf(route.Primary)
		result := value.MapIndex(key)
		if result.IsValid() {
			return result.Interface(), true
		}
	}
	return nil, false
}

func writeRouteTextData(w http.ResponseWriter, data any, message string) {
	if message == "" {
		message = "OK"
	}
	value := reflect.ValueOf(data)
	for value.IsValid() && (value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			value = reflect.Value{}
			break
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		_, _ = fmt.Fprintf(w, "OK: %s\n", message)
		return
	}
	if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		if value.Len() == 0 {
			_, _ = fmt.Fprintf(w, "OK: %s\n", message)
			return
		}
		_, _ = fmt.Fprintf(w, "OK: %d items found\n", value.Len())
		for i := 0; i < value.Len(); i++ {
			item := value.Index(i)
			if item.Kind() == reflect.Struct || (item.Kind() == reflect.Ptr && item.Elem().Kind() == reflect.Struct) {
				if i > 0 {
					_, _ = fmt.Fprintln(w)
				}
				writeRouteTextObject(w, item, "")
			} else {
				_, _ = fmt.Fprintln(w, routeTextScalar(item))
			}
		}
		return
	}
	_, _ = fmt.Fprintf(w, "OK: %s\n", message)
	if value.Kind() == reflect.Struct || value.Kind() == reflect.Map {
		writeRouteTextObject(w, value, "")
	}
}

func writeRouteTextObject(w http.ResponseWriter, value reflect.Value, prefix string) {
	for value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Struct:
		typeOf := value.Type()
		for i := 0; i < value.NumField(); i++ {
			field := typeOf.Field(i)
			tag := field.Tag.Get("json")
			parts := strings.Split(tag, ",")
			name := parts[0]
			if name == "-" || name == "" {
				name = field.Name
			}
			if field.PkgPath != "" {
				continue
			}
			if len(parts) > 1 && parts[1] == "omitempty" && value.Field(i).IsZero() {
				continue
			}
			writeRouteTextField(w, name, value.Field(i), prefix)
		}
	case reflect.Map:
		keys := value.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i].Interface()) < fmt.Sprint(keys[j].Interface()) })
		for _, key := range keys {
			writeRouteTextField(w, fmt.Sprint(key.Interface()), value.MapIndex(key), prefix)
		}
	}
}

func writeRouteTextField(w http.ResponseWriter, name string, value reflect.Value, prefix string) {
	if value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return
		}
		value = value.Elem()
	}
	if name == "" {
		return
	}
	key := name
	if prefix != "" {
		key = prefix + "." + name
	}
	if value.Kind() == reflect.Struct || value.Kind() == reflect.Map {
		writeRouteTextObject(w, value, key)
		return
	}
	if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		items := make([]string, value.Len())
		for i := 0; i < value.Len(); i++ {
			items[i] = fmt.Sprint(routeTextScalar(value.Index(i)))
		}
		_, _ = fmt.Fprintf(w, "%s: %s\n", key, strings.Join(items, ", "))
		return
	}
	_, _ = fmt.Fprintf(w, "%s: %v\n", key, routeTextScalar(value))
}

func routeTextScalar(value reflect.Value) any {
	for value.IsValid() && (value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return ""
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return ""
	}
	return value.Interface()
}
