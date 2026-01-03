package mood

type Type string

const (
	Happy         Type = "happy"
	Surprised     Type = "surprised"
	Uncomfortable Type = "uncomfortable"
	Down          Type = "down"
	Worried       Type = "worried"
	Frustrated    Type = "frustrated"
)

type ReasonType string

const (
	ReasonAchievement      ReasonType = "achievement"
	ReasonSocialConnection ReasonType = "socialConnection"
	ReasonSelfCare         ReasonType = "selfCare"
	ReasonGoodNews         ReasonType = "goodNews"

	ReasonUnexpectedNews ReasonType = "unexpectedNews"
	ReasonSomethingNew   ReasonType = "somethingNew"

	ReasonLoneliness     ReasonType = "loneliness"
	ReasonDisappointment ReasonType = "disappointment"
	ReasonLoss           ReasonType = "loss"
	ReasonExhaustion     ReasonType = "exhaustion"

	ReasonFrustration     ReasonType = "frustration"
	ReasonSomeoneBothered ReasonType = "someoneBothered"
	ReasonInjustice       ReasonType = "injustice"
	ReasonThingsWentWrong ReasonType = "thingsWentWrong"

	ReasonWorkDeadlines  ReasonType = "workDeadlines"
	ReasonUncertainty    ReasonType = "uncertainty"
	ReasonHealthWorries  ReasonType = "healthWorries"
	ReasonSocialPressure ReasonType = "socialPressure"

	ReasonOverwhelmed ReasonType = "overwhelmed"

	ReasonNoReason ReasonType = "noReason"
)

// ValidMoods for validation
var ValidMoods = map[Type]bool{
	Happy:         true,
	Surprised:     true,
	Uncomfortable: true,
	Down:          true,
	Worried:       true,
	Frustrated:    true,
}

// IsValidMood checks if mood is valid
func IsValidMood(mood string) bool {
	return ValidMoods[Type(mood)]
}

var ReasonMapping = map[Type][]ReasonType{
	Happy: {
		ReasonAchievement,
		ReasonSocialConnection,
		ReasonSelfCare,
		ReasonGoodNews,
		ReasonNoReason,
	},
	Surprised: {
		ReasonUnexpectedNews,
		ReasonSomethingNew,
		ReasonSocialConnection,
		ReasonAchievement,
		ReasonNoReason,
	},
	Uncomfortable: {
		ReasonSocialPressure,
		ReasonUncertainty,
		ReasonOverwhelmed,
		ReasonSomeoneBothered,
		ReasonNoReason,
	},
	Down: {
		ReasonLoneliness,
		ReasonDisappointment,
		ReasonLoss,
		ReasonExhaustion,
		ReasonNoReason,
	},
	Worried: {
		ReasonWorkDeadlines,
		ReasonUncertainty,
		ReasonHealthWorries,
		ReasonSocialPressure,
		ReasonNoReason,
	},
	Frustrated: {
		ReasonFrustration,
		ReasonSomeoneBothered,
		ReasonThingsWentWrong,
		ReasonInjustice,
		ReasonNoReason,
	},
}
