package masking

var (
	Name    = Policy{1, 1, '*'}
	Phone   = Policy{3, 2, '*'}
	Email   = Policy{2, 0, '*'}
	Address = Policy{6, 0, '*'}
)
