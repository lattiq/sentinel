package aws

// String returns a pointer to the string value passed in
func String(v string) *string {
	return &v
}

// Int32 returns a pointer to the int32 value passed in
func Int32(v int32) *int32 {
	return &v
}

// Int64 returns a pointer to the int64 value passed in
func Int64(v int64) *int64 {
	return &v
}

// Bool returns a pointer to the bool value passed in
func Bool(v bool) *bool {
	return &v
}

// Float64 returns a pointer to the float64 value passed in
func Float64(v float64) *float64 {
	return &v
}

// StringValue returns the value of the string pointer passed in or an empty string if the pointer is nil
func StringValue(v *string) string {
	if v != nil {
		return *v
	}
	return ""
}

// Int32Value returns the value of the int32 pointer passed in or 0 if the pointer is nil
func Int32Value(v *int32) int32 {
	if v != nil {
		return *v
	}
	return 0
}

// Int64Value returns the value of the int64 pointer passed in or 0 if the pointer is nil
func Int64Value(v *int64) int64 {
	if v != nil {
		return *v
	}
	return 0
}

// BoolValue returns the value of the bool pointer passed in or false if the pointer is nil
func BoolValue(v *bool) bool {
	if v != nil {
		return *v
	}
	return false
}

// Float64Value returns the value of the float64 pointer passed in or 0.0 if the pointer is nil
func Float64Value(v *float64) float64 {
	if v != nil {
		return *v
	}
	return 0.0
}
