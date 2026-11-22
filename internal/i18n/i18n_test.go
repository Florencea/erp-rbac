package i18n

import (
	"reflect"
	"strings"
	"testing"
)

func TestCatalogCompleteness(t *testing.T) {
	t.Parallel()

	for _, locale := range []string{LocaleZhTW, LocaleEnUS} {
		msg := Catalog(locale)
		assertNoEmptyStrings(t, locale, reflect.ValueOf(msg), "Messages")
	}
}

func assertNoEmptyStrings(t *testing.T, locale string, v reflect.Value, path string) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		if strings.TrimSpace(v.String()) == "" {
			t.Errorf("locale %s has empty translation at %s", locale, path)
		}
	case reflect.Struct:
		typ := v.Type()
		for i := range v.NumField() {
			f := typ.Field(i)
			assertNoEmptyStrings(t, locale, v.Field(i), path+"."+f.Name)
		}
	}
}
