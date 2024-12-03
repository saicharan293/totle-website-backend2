CREATE DATABASE USER_DB;
use user_db;
USE TOTLE_DB;

DROP DATABASE TOTLE_DB;

ALTER TABLE USER
ADD COLUMN image LONGBLOB;

SELECT * FROM LANGUAGE;


alter table user 
modify fullname varchar(255);

show tables;

DROP TABLE LANGUAGE;

DROP TABLE USER;

select * from user;

SELECT * FROM LANGUAGE;
alter table user
add googleId varchar(255) unique;

alter table user
rename column fullname To name;

alter table user
modify password varchar(255);

select * from user where email ='testcase@gmail.com';

DELETE FROM USER
WHERE email='john.doe@example.com';

select * from user; 


truncate table user;
