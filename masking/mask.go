package masking

type Policy struct {
	Prefix int
	Suffix int
	Char   rune
}

func Apply(value string, p Policy) string {
	r := []rune(value)
	if len(r) <= p.Prefix+p.Suffix {
		return value
	}

	out := make([]rune, 0, len(r))
	out = append(out, r[:p.Prefix]...)

	for i := 0; i < len(r)-p.Prefix-p.Suffix; i++ {
		out = append(out, p.Char)
	}

	out = append(out, r[len(r)-p.Suffix:]...)
	return string(out)
}
