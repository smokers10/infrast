package usermanagement

import (
	"errors"
	"fmt"
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
	TemplateProcessor    contract.TemplateProcessor
}

// Logout implements contract.UserManagement.
func (i *userManagementImplementation) Logout(device_id string) (httpStatus int, failure error) {
	if err := i.Repository.DeleteLoginSession(i.UserManagementConfig, device_id); err != nil {
		return 500, fmt.Errorf("error delete login session : %v", err.Error())
	}

	return 200, nil
}

// ForgotPassword implements contract.UserManagement
func (i *userManagementImplementation) ForgotPassword(credentials string) (tokens string, HTTPStatus int, failure error) {
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

	// send otp via SMTP/EMAIL or WA
	if user.Email != "" {
		data := map[string]interface{}{
			"reciever": user.Username,
			"otp":      otp,
		}

		template, err := i.TemplateProcessor.EmailTemplate(data, i.UserManagementConfig.ResetPassword.EmailTemplatePath)
		if err != nil {
			return "", 500, fmt.Errorf("error processing template : %v", err.Error())
		}

		if err := i.Mailer.Send([]string{user.Email}, "Atur Ulang Kata Sandi", template); err != nil {
			return "", 500, fmt.Errorf("error sending email : %v", err.Error())
		}
	}

	if user.PhoneNumber != "" {
		return "", 500, errors.New("unimplemented functionality")
	}

	return token, 200, failure
}

// Login implements contract.UserManagement
func (i *userManagementImplementation) Login(credential string, password string, device_id string) (user *contract.UserModel, token string, HTTPStatus int, failure error) {
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

		data := map[string]interface{}{
			"cancel_link": "localhost:8000/cancel-login/device-123",
		}
		template, err := i.TemplateProcessor.EmailTemplate(data, i.UserManagementConfig.UserDevice.EmailTemplatePath)
		if err != nil {
			return nil, "", 500, fmt.Errorf("error processing template : %v", err.Error())
		}

		if err := i.Mailer.Send([]string{}, "peringatan keamanan", template); err != nil {
			return nil, "", 500, fmt.Errorf("error send email : %v", err.Error())
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
	payload := map[string]interface{}{
		"user_id": user.ID,
		"type":    i.UserManagementConfig.SelectedCredential.Type,
		"iat":     time.Now().AddDate(0, 0, 7).Unix(),
	}

	// sign JWT token
	jwtToken, err := i.JWT.Sign(payload)
	if err != nil {
		return nil, "", 500, fmt.Errorf("token signing failure")
	}

	// remove user password for security measurement
	user.Password = ""

	return user, jwtToken, 200, nil
}

// RegisterNewAccount implements contract.UserManagement
func (i *userManagementImplementation) RegisterNewAccount(credential string, device_id string) (token string, HTTPStatus int, failure error) {
	// check if user exists or not
	user, err := i.Repository.FindOneUser(i.UserManagementConfig, credential)
	if err != nil {
		return "", 500, fmt.Errorf("error find one user : %v", err.Error())
	}

	if *user != (contract.UserModel{}) {
		return "", 401, fmt.Errorf("user with credential %v already registered", credential)
	}

	// check credential type
	credType := lib.CredentialChecker(credential)

	if credType == "email" {
		if lib.EmailChecker(credential) {
			token, status, err := i.emailRegistration(credential, device_id)
			if err != nil {
				return "", status, err
			}
			return token, status, err
		}
	}

	if credType == "phone" {
		isPhone, err := lib.PhoneChecker(credential)
		if err != nil {
			return "", 400, err
		}

		if isPhone {
			token, status, err := i.phoneRegistration(credential, device_id)
			if err != nil {
				return "", status, err
			}

			return token, status, err
		}
	}

	return "", 400, errors.New("uncertain registration request")
}

// RegisterVerification implements contract.UserManagement
func (i *userManagementImplementation) RegisterVerification(token string, otp string) (HTTPStatus int, failure error) {
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

// RegistrationBioData implements contract.UserManagement
func (i *userManagementImplementation) RegistrationBioData(credential string, query *contract.DynamicColumnValue) (user *contract.UserModel, tokens string, HTTPStatus int, failure error) {
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
		"iat":     time.Now().AddDate(0, 0, 7).Unix(),
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

// ResetPassword implements contract.UserManagement
func (i *userManagementImplementation) ResetPassword(token string, otp string, new_password string, conf_password string) (HTTPStatus int, failure error) {
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

	// new password and confirmation password must match
	if new_password != conf_password {
		return 400, errors.New("wrong confirmation password")
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

// register new account if credential is an email
func (i *userManagementImplementation) emailRegistration(credential string, device_id string) (token string, HTTPStatus int, failure error) {
	// generate OTP
	otp, err := i.UUID.GenerateOTP()
	if err != nil {
		return "", 500, err
	}

	// generate UUID id as registration token
	regToken, err := i.UUID.MakeIdentifier()
	if err != nil {
		return "", 500, fmt.Errorf("error generate token : %v", err.Error())
	}

	// secure otp
	secureOTP := i.Encryption.Hash(otp)

	// store registration data
	if err := i.Repository.CreateRegistration(i.UserManagementConfig, regToken, credential, secureOTP, device_id); err != nil {
		return "", 500, err
	}

	// processing email template
	data := map[string]interface{}{
		"otp": otp,
	}
	template, err := i.TemplateProcessor.EmailTemplate(data, i.UserManagementConfig.Registration.EmailTemplatePath)
	if err != nil {
		return "", 500, fmt.Errorf("error processing template : %v", err.Error())
	}

	// send otp over email
	if err := i.Mailer.Send([]string{i.GeneralConfig.SMTP.Sender}, "Registrasi Akun Baru", template); err != nil {
		return "", 500, errors.New("failed to send OTP")
	}

	return regToken, 200, nil
}

// register new accound if credential is a phone number
func (i *userManagementImplementation) phoneRegistration(credential string, device_id string) (token string, HTTPStatus int, failure error) {
	// generate OTP
	otp, err := i.UUID.GenerateOTP()
	if err != nil {
		return "", 500, err
	}

	// generate UUID id as registration token
	regToken, err := i.UUID.MakeIdentifier()
	if err != nil {
		return "", 500, fmt.Errorf("error generate token : %v", err.Error())
	}

	// secure otp
	secureOTP := i.Encryption.Hash(otp)

	// store registration data
	if err := i.Repository.CreateRegistration(i.UserManagementConfig, regToken, credential, secureOTP, device_id); err != nil {
		return "", 500, err
	}

	// send otp over email
	return "", 500, errors.New("unimplemented")
}

func UserManagement(configuration *config.Configuration, repository contract.UserManagementRepository, uuid contract.IdentfierContract, encryption contract.EncryptionContract, jwt contract.JsonWebTokenContract, mailer contract.MailerContract, template_processor contract.TemplateProcessor, user_type string) (contract.UserManagement, error) {
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
		UUID:                 uuid,
		TemplateProcessor:    template_processor,
	}, nil
}
