package rate

var routeLimits = map[string]int{
	"/signup": 50,
	"/signin": 5,
}