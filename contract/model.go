package contract

type UserModel struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	PhotoProfile string `json:"photo_profile"`
	PhoneNumber  string `json:"phone_number"`
}

type ForgotPasswordModel struct {
	ID         int
	Token      string
	OTP        string
	Credential string
	CreatedAt  int64
	Type       string
}

type RegistrationModel struct {
	ID                 int
	Token              string
	OTP                string
	Credential         string
	CreatedAt          int64
	Type               string
	RegistrationStatus string
	DeviceID           string
	FCMToken           string
}

type LoginModel struct {
	ID            int
	Token         string
	Credential    string
	Type          string
	DeviceID      string
	LoginAt       int64
	AttemptAt     int64
	FailedCounter int
}

type UserDeviceModel struct {
	ID       int
	DeviceID string
	UserID   int
	UserType string
}

type UserFCMTokenModel struct {
	ID        int
	Token     string
	Timestamp int64
	UserType  string
	UserID    string
}

type DynamicColumnValue struct {
	Column string
	Value  []string
}
