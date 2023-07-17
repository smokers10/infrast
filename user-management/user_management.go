package usermanagement

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/smokers10/infrast/lib"
)

type userManagementImplementation struct {
	UserManagementConfig *config.UserManagementConfig
	GeneralConfig        *config.Configuration
	Repository           contract.UserManagementRepository
	UUID                 contract.IdentfierContract
	Encryption           contract.EncryptionContract
	JWT                  contract.JsonWebTokenContract
	Mailer               contract.MailerContract
	Whatsapp             contract.Whatsapp
	TemplateProcessor    contract.TemplateProcessor
}

func (i *userManagementImplementation) CheckUserJWTToken(device_id string) (checkResponse map[string]interface{}, HTTPStatus int, failure error) {
	if device_id == "" {
		return nil, 400, fmt.Errorf("incomplete required data\ndevice id : %s", device_id)
	}

	login, err := i.Repository.FindOneLoginSession(i.UserManagementConfig, device_id)
	if err != nil {
		return nil, 500, fmt.Errorf("error find one login session : %v", err.Error())
	}

	if *login == (contract.LoginModel{}) {
		return nil, 404, fmt.Errorf("login session not exists")
	}

	payload, err := i.JWT.ParseToken(login.Token)
	if err != nil {
		return nil, 500, fmt.Errorf("error parse jwt token : %v", err.Error())
	}

	parsePayload := lib.ParsePayload(payload)
	curentTime := time.Now().UTC().Unix()

	if curentTime > parsePayload.Eat {
		checkResponse = map[string]interface{}{
			"check_result": "expired",
			"message":      "please refresh your token",
		}

		return checkResponse, 200, nil
	}

	checkResponse = map[string]interface{}{
		"check_result": "ok",
		"message":      "your token still usable",
	}

	return checkResponse, 200, nil
}

func (i *userManagementImplementation) UpdateUserJWTToken(user_id int, device_id string) (token string, HTTPStatus int, failure error) {
	if user_id == 0 || device_id == "" {
		return "", 400, fmt.Errorf("incomplete required data\nuser id : %d\ndevice id : %s", user_id, device_id)
	}

	device, err := i.Repository.FindUserDevice(i.UserManagementConfig, user_id, device_id)
	if err != nil {
		return "", 500, fmt.Errorf("error find user device : %v", err.Error())
	}

	if *device == (contract.UserDeviceModel{}) {
		return "", 404, fmt.Errorf("user device id %s not registered", device_id)
	}

	jwtToken, err := i.JWT.Sign(lib.MakeJWTPayload(device.UserID, *i.UserManagementConfig))
	if err != nil {
		return "", 500, fmt.Errorf("token signing failure")
	}

	if err := i.Repository.UpdateJWTToken(i.UserManagementConfig, jwtToken, device_id); err != nil {
		return "", 500, fmt.Errorf("error update JWT token : %v", err.Error())
	}

	return jwtToken, 200, nil
}

func (i *userManagementImplementation) UpdateUserCredential(new_credential string, current_password string, user_id int, credential_property string) (HTTPStatus int, failure error) {
	selectedCred := i.UserManagementConfig.SelectedCredential

	// validate required data
	if new_credential == "" || current_password == "" || user_id == 0 {
		return 400, fmt.Errorf("incomplete required data\nnew credential : %s\ncurrent password : %s\nuser id : %d\ncredential property : %s", new_credential, current_password, user_id, credential_property)
	}

	// credential property must marked credential property
	isMarked := false
	for i := 0; i < len(selectedCred.Credential); i++ {
		if selectedCred.Credential[i] == credential_property {
			isMarked = true
			break
		}
	}

	if !isMarked {
		return 400, fmt.Errorf("property '%s' is not marked as credential on configuration", credential_property)
	}

	// fetch user to get password
	user, err := i.Repository.FindOneUserByID(i.UserManagementConfig, user_id)
	if err != nil {
		return 500, fmt.Errorf("error find one user by id : %v", err.Error())
	}

	if *user == (contract.UserModel{}) {
		return 404, fmt.Errorf("user with not registered")
	}

	// compare password
	if !i.Encryption.Compare(current_password, user.Password) {
		return 401, fmt.Errorf("wrong password")
	}

	// update selected credential
	if err := i.Repository.UpdateCredential(i.UserManagementConfig, new_credential, user_id, credential_property); err != nil {
		return 500, fmt.Errorf("error update credential : %v", err.Error())
	}

	return 200, nil
}

func (i *userManagementImplementation) UpdateUserPassword(new_password string, confirmation_password string, user_id int) (HTTPStatus int, failure error) {
	if user_id == 0 || new_password == "" || confirmation_password == "" || confirmation_password != new_password {
		return http.StatusBadRequest, fmt.Errorf("incomplete or mismatched confirmation\n"+
			"user id: %v\n"+
			"new password: %v\n"+
			"confirmation password: %v",
			user_id, new_password, confirmation_password)
	}

	user, err := i.Repository.FindOneUserByID(i.UserManagementConfig, user_id)
	if err != nil {
		return 500, fmt.Errorf("error find one user by its id : %v", err.Error())
	}

	if *user == (contract.UserModel{}) {
		return 404, fmt.Errorf("user not registered")
	}

	if !i.Encryption.Compare(confirmation_password, user.Password) {
		return 401, fmt.Errorf("wrong password")
	}

	new_password = i.Encryption.Hash(new_password)

	if err := i.Repository.UpdateUserPasswordByUserID(i.UserManagementConfig, new_password, user_id); err != nil {
		return 500, fmt.Errorf("errof update user password by user id : %v", err.Error())
	}

	return 200, nil
}

func (i *userManagementImplementation) UpsertUserFCMToken(token string, user_id int) (HTTPStatus int, failure error) {
	if token == "" || user_id == 0 {
		return 400, fmt.Errorf("incomplete required data\n token : %s\nuser id : %v", token, user_id)
	}

	timestamp := time.Now().UTC().Unix()

	FCMToken, err := i.Repository.GetFCMToken(i.UserManagementConfig, user_id)
	if err != nil {
		return 500, fmt.Errorf("error get FCM tokn : %v", err.Error())
	}

	// if fcm is not exists the insert fcm
	if *FCMToken == (contract.UserFCMTokenModel{}) {
		if err := i.Repository.StoreFCMToken(i.UserManagementConfig, token, timestamp, user_id); err != nil {
			return 500, fmt.Errorf("error store FCM token : %v", err.Error())
		}

		return 200, nil
	}

	if err := i.Repository.UpdateFCMToken(i.UserManagementConfig, token, timestamp, user_id); err != nil {
		return 500, fmt.Errorf("error update FCM token : %v", err.Error())
	}

	return 200, nil
}

func (i *userManagementImplementation) Logout(device_id string) (httpStatus int, failure error) {
	if device_id == "" {
		return http.StatusBadRequest, fmt.Errorf("device id is empty")
	}

	if err := i.Repository.DeleteLoginSession(i.UserManagementConfig, device_id); err != nil {
		return 500, fmt.Errorf("error delete login session : %v", err.Error())
	}

	return 200, nil
}

func (i *userManagementImplementation) ForgotPassword(credentials string) (tokens string, HTTPStatus int, failure error) {
	if credentials == "" {
		return "", http.StatusBadRequest, fmt.Errorf("credential is empty")
	}

	// check credential type
	credentialType := lib.CredentialChecker(credentials)

	// check valid and active email
	if credentialType == "email" {
		if !lib.EmailChecker(credentials) {
			return "", 400, fmt.Errorf("invalid email %s", credentials)
		}
	}

	// check phone number validity
	if credentialType == "phone" {
		_, err := lib.PhoneChecker(credentials)
		if err != nil {
			return "", 400, fmt.Errorf("error parsing phone number : %v", err.Error())
		}
	}

	// check if user exists or not
	user, err := i.Repository.FindOneUser(i.UserManagementConfig, credentials)
	if err != nil {
		return "", 500, fmt.Errorf("error find one user : %v", err.Error())
	}

	// if not exists
	if *user == (contract.UserModel{}) {
		return "", 404, fmt.Errorf("user with credential %v not found", credentials)
	}

	// create forgot password token
	token, err := i.UUID.MakeIdentifier()
	if err != nil {
		return "", 500, fmt.Errorf("error make identifier : %v", err.Error())
	}

	// generate otp
	otp, err := i.UUID.GenerateOTP()
	if err != nil {
		return "", 500, fmt.Errorf("error make OTP : %v", err.Error())
	}

	// make encrypted otp
	safeOTP := i.Encryption.Hash(otp)

	// store forgot password
	if err := i.Repository.StoreForgotPassword(i.UserManagementConfig, credentials, token, safeOTP); err != nil {
		return "", 500, fmt.Errorf("error store forgot password : %v", err.Error())
	}

	if credentialType == "email" {
		data := map[string]interface{}{
			"reciever": user.Username,
			"otp":      otp,
		}

		template, err := i.TemplateProcessor.EmailTemplate(data, i.UserManagementConfig.MessageTemplate.ForgotPasswordEmailTemplatePath)
		if err != nil {
			return "", 500, fmt.Errorf("error processing template : %v", err.Error())
		}

		if err := i.Mailer.Send([]string{user.Email}, "Atur Ulang Kata Sandi", template); err != nil {
			return "", 500, fmt.Errorf("error sending email : %v", err.Error())
		}
	}

	if credentialType == "phone" {
		template := fmt.Sprintf(i.UserManagementConfig.MessageTemplate.ForgotPasswordMessageTemplate, otp)
		if err := i.Whatsapp.SendMessage(template, credentials); err != nil {
			return "", 500, fmt.Errorf("error WA : %v", err.Error())
		}
	}

	return token, 200, failure
}

func (i *userManagementImplementation) Login(credential string, password string, device_id string) (user *contract.UserModel, token string, HTTPStatus int, failure error) {
	if credential == "" || password == "" || device_id == "" {
		return nil, "", http.StatusBadRequest, fmt.Errorf("incomplete required data\ncredential : %v\npassword : %v\ndevice id : %v", credential, password, device_id)
	}

	// check if user exists or not
	user, err := i.Repository.FindOneUser(i.UserManagementConfig, credential)
	if err != nil {
		return nil, "", 500, fmt.Errorf("error find one user : %v", err.Error())
	}

	// if not exists
	if *user == (contract.UserModel{}) {
		return nil, "", 404, fmt.Errorf("user with credential %v not found", credential)
	}

	// check device id registered or not
	device, err := i.Repository.FindUserDevice(i.UserManagementConfig, user.ID, device_id)
	if err != nil {
		return nil, "", 500, fmt.Errorf("error find user device : %v", err.Error())
	}

	// if device id is not registered then register user device and send security concern email
	if *device == (contract.UserDeviceModel{}) {
		if err := i.Repository.CreateNewUserDevice(i.UserManagementConfig, user.ID, device_id); err != nil {
			return nil, "", 500, fmt.Errorf("error create user device : %v", err.Error())
		}
		credentialType := lib.CredentialChecker(credential)
		cancelationURL := fmt.Sprintf(i.UserManagementConfig.MessageTemplate.LoginCancelationURL, device_id)

		if credentialType == "email" {
			data := map[string]interface{}{
				"logout_url": cancelationURL,
				"logged_at":  time.Now().UTC().Local().Format("2006-01-02 3:4 pm"),
			}

			template, err := i.TemplateProcessor.EmailTemplate(data, i.UserManagementConfig.MessageTemplate.NewDeviceWarningEmailTemplatePath)
			if err != nil {
				return nil, "", 500, fmt.Errorf("error processing template : %v", err.Error())
			}

			if err := i.Mailer.Send([]string{}, "Peringatan Keamanan", template); err != nil {
				return nil, "", 500, fmt.Errorf("error send email : %v", err.Error())
			}
		}

		if credentialType == "phone" {
			phoneIsParsed, err := lib.PhoneChecker(credential)
			if err != nil {
				return nil, "", 400, err
			}

			if phoneIsParsed {
				template := fmt.Sprintf(i.UserManagementConfig.MessageTemplate.NewDeviceWarningMessageTemplate, cancelationURL)
				if err := i.Whatsapp.SendMessage(template, credential); err != nil {
					return nil, "", 500, fmt.Errorf("error WA : %v", err.Error())
				}
			}
		}
	}

	// check if user with provided device id has attempted to login or not
	login, err := i.Repository.FindOneLoginSession(i.UserManagementConfig, device_id)
	if err != nil {
		return nil, "", 500, fmt.Errorf("error find one login session : %v", err.Error())
	}

	// if login attempt not then found create one
	if *login == (contract.LoginModel{}) {
		if err := i.Repository.CreateNewLoginSession(i.UserManagementConfig, credential, device_id); err != nil {
			return nil, "", 500, fmt.Errorf("error create login session : %v", err.Error())
		}
	}

	// if login attempt found and crendential is different then update login session credential
	if *login != (contract.LoginModel{}) && login.Credential != credential {
		if err := i.Repository.UpdateLoginCredential(i.UserManagementConfig, device_id, credential); err != nil {
			return nil, "", 500, fmt.Errorf("error create login session : %v", err.Error())
		}
	}

	// check failed login attempt
	if login.FailedCounter >= i.UserManagementConfig.Login.MaxFailedAttempt {
		currentTime := time.Unix(time.Now().Unix(), 0)
		attemptTime := time.Unix(int64(login.AttemptAt), 0)
		rawTimeRange := currentTime.Sub(attemptTime)
		timeRange := int(rawTimeRange.Seconds())

		if timeRange > i.UserManagementConfig.Login.LoginBlockDuration {
			return nil, "", 401, errors.New("too many failed login attempt, try again later")
		} else {
			if err := i.Repository.UpdateLoginFailedAttempt(i.UserManagementConfig, device_id, 0); err != nil {
				return nil, "", 500, fmt.Errorf("error update login failed attempt : %v", err.Error())
			}
		}
	}

	// check if registration is verified or not
	reg, err := i.Repository.FindOneRegistrationByCredential(i.UserManagementConfig, credential)
	if err != nil {
		return nil, "", 500, fmt.Errorf("error find one registration by credential : %v", err.Error())
	}

	// if registration not found / empty
	if *reg == (contract.RegistrationModel{}) {
		return nil, "", 404, fmt.Errorf("user with credential %v unregistered", credential)
	}

	// if registration not verified
	if reg.RegistrationStatus != "verified" {
		return nil, "", 401, fmt.Errorf("user with credential %v unverified registration", credential)
	}

	// compare password then
	if !i.Encryption.Compare(password, user.Password) {
		if err := i.Repository.UpdateLoginFailedAttempt(i.UserManagementConfig, device_id, login.FailedCounter+1); err != nil {
			return nil, "", 500, fmt.Errorf("error find update login failed attempt : %v", err.Error())
		}
		return nil, "", 401, fmt.Errorf("wrong authentication credential")
	}

	// make token
	payload := lib.MakeJWTPayload(user.ID, *i.UserManagementConfig)

	// sign JWT token
	jwtToken, err := i.JWT.Sign(payload)
	if err != nil {
		return nil, "", 500, fmt.Errorf("token signing failure")
	}

	// remove user password for security measurement
	user.Password = ""

	return user, jwtToken, 200, nil
}

func (i *userManagementImplementation) RegisterNewAccount(credential string, device_id string) (token string, HTTPStatus int, failure error) {
	if credential == "" || device_id == "" {
		return "", http.StatusBadRequest, fmt.Errorf("incomplete required data\ncredential : %v\ndevice id : %v", credential, device_id)
	}

	credentialType := lib.CredentialChecker(credential)

	if credentialType == "email" {
		if lib.EmailChecker(credential) {
			regToken, otp, status, err := i.registrationLogic(credential, device_id)
			if err != nil {
				return "", status, err
			}

			if err := i.sendEmailRegistration(otp, credential); err != nil {
				return "", 500, fmt.Errorf("error SMTP send : %v", err)
			}

			return regToken, status, err
		}
	}

	if credentialType == "phone" {
		isPhone, err := lib.PhoneChecker(credential)
		if err != nil {
			return "", 400, err
		}

		if isPhone {
			regToken, otp, status, err := i.registrationLogic(credential, device_id)
			if err != nil {
				return "", status, err
			}

			if err := i.SendMessageRegistration(otp, credential); err != nil {
				return "", 500, fmt.Errorf("error send whatsapp : %v", err)
			}

			return regToken, status, err
		}
	}

	return "", 400, errors.New("uncertain credential")
}

func (i *userManagementImplementation) RegisterVerification(token string, otp string) (HTTPStatus int, failure error) {
	if token == "" || otp == "" {
		return http.StatusBadRequest, fmt.Errorf("incomplete required data\ntoken : %v\nOTP : %v", token, otp)
	}

	// find registration data by token
	reg, err := i.Repository.FindOneRegistration(i.UserManagementConfig, token)
	if err != nil {
		return 500, err
	}

	// if registration not found
	if *reg == (contract.RegistrationModel{}) {
		return 404, errors.New("registration not found")
	}

	// if registration verficiation status is verified
	if reg.RegistrationStatus == "verified" {
		return 401, errors.New("your registration already verified")
	}

	// compare OTP
	if !i.Encryption.Compare(otp, reg.OTP) {
		return 401, errors.New("wrong OTP code")
	}

	// if OTP correct
	if err := i.Repository.UpdateStatusRegistration(i.UserManagementConfig, token); err != nil {
		return 500, fmt.Errorf("error update registration : %v", err.Error())
	}

	return 200, nil
}

func (i *userManagementImplementation) RegistrationBioData(credential string, query *contract.DynamicColumnValue) (user *contract.UserModel, tokens string, HTTPStatus int, failure error) {
	if credential == "" || query == nil {
		return nil, "", http.StatusBadRequest, fmt.Errorf("incomplete required data\ncredential : %v\nquery : %v", credential, query)
	}

	// check if user exists or not
	user, err := i.Repository.FindOneUser(i.UserManagementConfig, credential)
	if err != nil {
		return nil, "", 500, err
	}

	if *user != (contract.UserModel{}) {
		return nil, "", 400, fmt.Errorf("user with credential %v already registered", credential)
	}

	// find registration data
	reg, err := i.Repository.FindOneRegistrationByCredential(i.UserManagementConfig, credential)
	if err != nil {
		return nil, "", 500, fmt.Errorf("error find one registration by credential : %v", err.Error())
	}

	if *reg == (contract.RegistrationModel{}) {
		return nil, "", 404, fmt.Errorf("registration with credential %v not found", credential)
	}

	// insert user
	_, err = i.Repository.StoreUser(i.UserManagementConfig, query.Column, query.Value...)
	if err != nil {
		return nil, "", 500, fmt.Errorf("error store user : %v", err.Error())
	}

	// find inserted user
	insertedUser, err := i.Repository.FindOneUser(i.UserManagementConfig, credential)
	if err != nil {
		return nil, "", 500, fmt.Errorf("error find one user : %v", err.Error())
	}

	// if inserted user not found
	if *insertedUser == (contract.UserModel{}) {
		return nil, "", 404, fmt.Errorf("inserted user not found")
	}

	// insert user device
	if err := i.Repository.CreateNewUserDevice(i.UserManagementConfig, insertedUser.ID, reg.DeviceID); err != nil {
		return nil, "", 500, fmt.Errorf("error store user device : %v", err.Error())
	}

	// make token
	payload := map[string]interface{}{
		"user_id": user.ID,
		"type":    i.UserManagementConfig.SelectedCredential.Type,
		"iat":     time.Now().UTC().Unix(),
		"eat":     time.Now().UTC().AddDate(0, 0, 7).Unix(),
	}

	// sign jwt token
	jwtToken, err := i.JWT.Sign(payload)
	if err != nil {
		return nil, "", 500, fmt.Errorf("token signing failure : %v", err.Error())
	}

	// remove user password for security measurement
	user.Password = ""

	return insertedUser, jwtToken, 200, nil
}

func (i *userManagementImplementation) ResetPassword(token string, otp string, new_password string, conf_password string) (HTTPStatus int, failure error) {
	if token == "" || otp == "" || new_password == "" || conf_password == "" || conf_password != new_password {
		return http.StatusBadRequest, fmt.Errorf("incomplete or mismatched confirmation\n"+
			"token: %v\n"+
			"otp: %v\n"+
			"new password: %v\n"+
			"confirmation password: %v",
			token, otp, new_password, conf_password)
	}

	// check if reset password data is exist or not
	fp, err := i.Repository.FindOneForgotPassword(i.UserManagementConfig, token)
	if err != nil {
		return 500, err
	}

	// check validity duration
	createdAt := time.Unix(fp.CreatedAt, 0)
	currentTime := time.Unix(time.Now().Unix(), 0)
	timeRange := int(currentTime.Sub(createdAt))
	if timeRange > i.UserManagementConfig.ResetPassword.ValidityDuration {
		// delete reset password session
		if err := i.Repository.DeleteForgotPassword(i.UserManagementConfig, token); err != nil {
			return 500, fmt.Errorf("error delete forgot password : %v", err.Error())
		}

		return 400, errors.New("reset password session expired")
	}

	// if reset otp wrong
	if !i.Encryption.Compare(otp, fp.OTP) {
		return 401, errors.New("wrong reset password OTP")
	}

	// create safe password
	safePassword := i.Encryption.Hash(new_password)

	// if reset otp correct update password
	if err := i.Repository.UpdateUserPassword(i.UserManagementConfig, fp.Credential, safePassword); err != nil {
		return 500, err
	}

	// delete reset password session
	if err := i.Repository.DeleteForgotPassword(i.UserManagementConfig, token); err != nil {
		return 500, fmt.Errorf("error delete forgot password : %v", err.Error())
	}

	return 200, nil
}

func (i *userManagementImplementation) registrationLogic(credential string, device_id string) (token string, otp string, HTTPStatus int, failure error) {
	// check is already user exists or not
	user, err := i.Repository.FindOneUser(i.UserManagementConfig, credential)
	if err != nil {
		return "", "", 500, fmt.Errorf("error find one user : %v", err.Error())
	}

	if *user != (contract.UserModel{}) {
		return "", "", 401, fmt.Errorf("user with credential %v already registered", credential)
	}

	// generate OTP
	otp, err = i.UUID.GenerateOTP()
	if err != nil {
		return "", "", 500, err
	}

	// generate UUID id as registration token
	regToken, err := i.UUID.MakeIdentifier()
	if err != nil {
		return "", "", 500, fmt.Errorf("error generate token : %v", err.Error())
	}

	// secure otp
	secureOTP := i.Encryption.Hash(otp)

	// check registration data
	registration, err := i.Repository.FindOneRegistrationByCredential(i.UserManagementConfig, credential)
	if err != nil {
		return "", "", 500, fmt.Errorf("error find one registration by credential : %v", err.Error())
	}

	// if registration data is found then update if not create new one
	if *registration != (contract.RegistrationModel{}) {
		if err := i.Repository.UpdateRegistration(i.UserManagementConfig, regToken, credential, secureOTP, device_id, time.Now().Unix()); err != nil {
			return "", "", 500, fmt.Errorf("error update registration : %v", err.Error())
		}
	} else {
		if err := i.Repository.CreateRegistration(i.UserManagementConfig, regToken, credential, secureOTP, device_id, time.Now().Unix()); err != nil {
			return "", "", 500, err
		}
	}

	return regToken, otp, 200, nil
}

func (i *userManagementImplementation) sendEmailRegistration(otp string, credential string) (failure error) {
	// processing email template
	data := map[string]interface{}{
		"otp": otp,
	}

	template, err := i.TemplateProcessor.EmailTemplate(data, i.UserManagementConfig.MessageTemplate.NewRegistrationEmailTemplatePath)
	if err != nil {
		return fmt.Errorf("error processing template : %v", err.Error())
	}

	// send otp over email
	if err := i.Mailer.Send([]string{credential}, "Registrasi Akun Baru", template); err != nil {
		return fmt.Errorf("error send OTP email : %v", err.Error())
	}

	return nil
}

func (i *userManagementImplementation) SendMessageRegistration(otp string, credential string) (failure error) {
	message := fmt.Sprintf(i.UserManagementConfig.MessageTemplate.NewRegistrationMessageTemplate, otp)

	if err := i.Whatsapp.SendMessage(message, credential); err != nil {
		return err
	}

	return nil
}

func UserManagement(configuration *config.Configuration, repository contract.UserManagementRepository, uuid contract.IdentfierContract, encryption contract.EncryptionContract, jwt contract.JsonWebTokenContract, mailer contract.MailerContract, wa contract.Whatsapp, template_processor contract.TemplateProcessor, user_type string) (contract.UserManagement, error) {
	selectedUserCredential := config.UserCredential{}
	for _, v := range configuration.UserManagement.UserCredential {
		if v.Type == user_type {
			selectedUserCredential = v
			break
		}
	}

	if selectedUserCredential.Type != user_type {
		return nil, errors.New("user type not registered")
	}

	configuration.UserManagement.SelectedCredential = selectedUserCredential

	return &userManagementImplementation{
		UserManagementConfig: &configuration.UserManagement,
		GeneralConfig:        configuration,
		Repository:           repository,
		Encryption:           encryption,
		JWT:                  jwt,
		Mailer:               mailer,
		Whatsapp:             wa,
		UUID:                 uuid,
		TemplateProcessor:    template_processor,
	}, nil
}
