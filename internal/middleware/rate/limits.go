package rate

var routeLimits = map[string]int{
	"/signup": 5,
	"/signin": 5,
}