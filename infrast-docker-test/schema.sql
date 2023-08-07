-- public.devices definition

-- Drop table

-- DROP TABLE public.devices;

CREATE TABLE public.devices (
	id int8 NOT NULL GENERATED ALWAYS AS IDENTITY( INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START 1 CACHE 1 NO CYCLE),
	device_id text NULL,
	user_id int8 NULL,
	user_type varchar(10) NULL,
	CONSTRAINT devices_pkey PRIMARY KEY (id)
);


-- public.login definition

-- Drop table

-- DROP TABLE public.login;

CREATE TABLE public.login (
	id int8 NOT NULL GENERATED ALWAYS AS IDENTITY( INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START 1 CACHE 1 NO CYCLE),
	jwt_token text NULL,
	device_id text NULL,
	credential varchar(50) NULL,
	failed_attempt int8 NULL DEFAULT 0,
	logged_at int8 NULL,
	attempted_at int8 NULL,
	user_type varchar(10) NULL,
	CONSTRAINT login_pkey PRIMARY KEY (id)
);


-- public.registration definition

-- Drop table

-- DROP TABLE public.registration;

CREATE TABLE public.registration (
	id int8 NOT NULL GENERATED ALWAYS AS IDENTITY( INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START 1 CACHE 1 NO CYCLE),
	credential varchar(50) NULL,
	registration_token text NULL,
	otp text NULL,
	status varchar(10) NULL,
	device_id text NULL,
	user_type varchar(10) NULL,
	fcm_token text NULL,
	created_at int4 NULL,
	CONSTRAINT registration_pkey PRIMARY KEY (id)
);


-- public.reset_password definition

-- Drop table

-- DROP TABLE public.reset_password;

CREATE TABLE public.reset_password (
	id int8 NOT NULL GENERATED ALWAYS AS IDENTITY( INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START 1 CACHE 1 NO CYCLE),
	"token" text NULL,
	otp text NULL,
	user_type varchar(10) NULL,
	credential varchar(50) NULL,
	created_at int8 NULL,
	CONSTRAINT reset_password_pkey PRIMARY KEY (id)
);


-- public.user_fcm definition

-- Drop table

-- DROP TABLE public.user_fcm;

CREATE TABLE public.user_fcm (
	id int8 NOT NULL GENERATED ALWAYS AS IDENTITY( INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START 1 CACHE 1 NO CYCLE),
	fcm_token text NULL,
	fcm_timestamp int8 NULL,
	user_type varchar(10) NULL,
	user_id int8 NULL,
	CONSTRAINT user_fcm_pkey PRIMARY KEY (id)
);


-- public.users definition

-- Drop table

-- DROP TABLE public.users;

CREATE TABLE public.users (
	id int8 NOT NULL GENERATED ALWAYS AS IDENTITY( INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START 1 CACHE 1 NO CYCLE),
	username varchar(30) NULL,
	email varchar(50) NULL,
	phone varchar(15) NULL,
	address text NULL,
	"password" text NULL,
	created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
	photo_profile text NULL,
	CONSTRAINT users_pkey PRIMARY KEY (id)
);