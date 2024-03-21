const express = require('express');
const router = express.Router();

//mongoDB user model
const User = require('./../models/User');

//mongoDB user verification model
const UserVerification = require('./../models/UserVerification');

//mongoDB user otp verification model
const UserOTPVerification = require("./../models/userOTPVerification");


//email Handler
const nodemailer = require("nodemailer");

//Unique String
const {v4: uuidv4} = require("uuid");

//env variables
require("dotenv").config();

//Password handler
const bcrypt = require ('bcrypt');

//path for static verified page
const path = require("path");

////nodemailer stuff
let transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.AUTH_EMAIL,
        pass: process.env.AUTH_PASS,
    }
})

//Testing Success
transporter.verify((error, success) =>{
    if(error) {
        console.log(error)
    }else{
        console.log("Ready for messages");
        console.log(success);
    }
})

//Signup
router.post('/signup',(req, res) => {
    let { name, email, password, dateOfBirth} = req.body;
    name = name.trim();
    email = email.trim();
    password = password.trim();
    dateOfBirth = dateOfBirth.trim();

    if (name == "" || email == "" || password == "" || dateOfBirth == "") {
        res.json({
            status: "FAILED",
            message: "Input fields are empty!"
        });
    }else if(!/^[a-zA-Z]*$/.test(name)){
        res.json({
            status: "FAILED",
            message: "Invalid entry in the Name field!"
        })
    }else if(!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)){
        res.json({
            status: "FAILED",
            message: "Invalid entry in the Email field!"
        })
    }else if (!new Date(dateOfBirth).getTime()){
        res.json({
            status: "FAILED",
            message: "Invalid Date of Birth entered!"
        })
    }else if (password.length < 8){
        res.json({
            status: "FAILED",
            message: "Password entered is too short!"
        })
    }else{
        //Checking if user already exists
        User.find({email}).then(result=>{
            if (result.length){
                //User already exists
                res.json({
                    status: "FAILED",
                    message: "User with provided email already exists"
                })
            }else{
                //Try to create new User

                //password handling
                const saltRounds = 10;
                bcrypt.hash(password, saltRounds).then(hashedPassword =>{
                    const newUser = new User({
                        name,
                        email,
                        password: hashedPassword,
                        dateOfBirth,
                        verified: false,
                    });

                    newUser
                    .save()
                    .then(result =>{
                       //handle verification
                       //sendVerificationEmail(result, res);
                       sendOTPVerificationEmail(result, res);
                    })
                    .catch(err =>{
                        res.json({
                            status: "FAILED",
                            message: "Error occured while saving user account!"
                        })
                    })
                })
                .catch(err => {
                    res.json({
                        status: "FAILED",
                        message: "Error occured while hashing password!"
                    })
                })
            }
        }).catch(err=>{
            console.log(err);
            res.json({
                status: "FAILED",
                message: "An error occured while checking for exsisting user!"
            })
        })
    }
})

//send verification email
const sendVerificationEmail = ({_id, email}, res) => {
    //url to be used in the email
    const currentUrl = "http://localhost:3037/";

    const uniqueString = uuidv4() + _id;

    //mail options
    const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Verify your Email",
        html: `<p>Verify your email address to complete the signup and login into your account.</p><p>This Link expires in six hours.</p><p>Press <a href=${currentUrl + "user/verify/" + _id + "/" + uniqueString}>here</a> to proceed.</p>`,
    };

    //hash the unique string
    const saltRounds = 10;
    bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
        //set values in userVerification collection
        const newVerification = new UserVerification({
            userId:  _id,
            uniqueString: hashedUniqueString,
            createdAt: Date.now(),
            expiresAt: Date.now() + 21600000, 
        });

        newVerification
        .save()
        .then(()=>{
            transporter
            .sendMail(mailOptions)
            .then(() =>{
                //email sent and verification record saved
                res.json({
                    status: "PENDING",
                    message: "Verification Email sent!",

                })
            })
            .catch((error) => {
                console.log(error);
                res.json({
                    status: "FAILED",
                    message: "verification Mail Failed!",
            });
        })
        })
        .catch((error) =>{
            console.log(error);
            res.json({
                status: "FAILED",
                message: "Could not save verification Email data!",
        })
    })
    .catch(() =>{
        res.json({
            status: "FAILED",
            message: "An error occured while hashing email data!",
        })
    })
})
};

//verify email
router.get("/verify/:userId/:uniqueString", (req, res) =>{
    let { userId, uniqueString } = req.params;

    UserVerification
    .find({userId})
    .then((result) =>{
        if(result.length > 0){
            //user verification record exists so we proceed

            const {expiresAt} = result[0];
            const hashedUniqueString = result[0].uniqueString;

            //checking for expired unique string
            if(expiresAt < Date.now()){
                //record has expired so we delete it
                UserVerification
                  .deleteOne({userId})
                  .then(result =>{
                    User
                    .deleteOne({_id: userId})
                    .then(()=>{
                        let message = "Link has expired. Please signup again.";
                        res.redirect(`/user/verified/error=true&message=${message}`);
                    })
                    .catch((error) =>{
                        let message = "Clearing user with expired unique string failed!";
                        res.redirect(`/user/verified/error=true&message=${message}`);
                    })
                  })
                  .catch((error) =>{
                    console.log(error);
                    let message = "An error occured while clearing expired user verification record!";
                    res.redirect(`/user/verified/error=true&message=${message}`);
                  })
            }else{
                //valid record exists so we validate the user string
                //first compare the hashed unique string

                bcrypt
                .compare(uniqueString, hashedUniqueString)
                .then(result => {
                    if(result){
                        //strings match

                        User
                        .updateOne({_id: userId}, {verified:true})
                        .then(() => {
                            UserVerification
                             .deleteOne({userId})
                             .then(() => {
                                res.sendFile(path.join(__dirname, "./../views/verified.html"));
                             })
                             .catch(error =>{
                                console.log(error);
                                let message = "An error occured while finalizing successful verification!";
                                res.redirect(`/user/verified/error=true&message=${message}`);
                             })
                        })
                        .catch(error =>{
                            console.log(error);
                            let message = "An error occured while updating user record to shoe verified.";
                            res.redirect(`/user/verified/error=true&message=${message}`);
                        })

                    }else{
                        //existing record but incorrect verification details passed
                        let message = "Invalid varification details passed. Check your Inbox.";
                        res.redirect(`/user/verified/error=true&message=${message}`);
                    }
                })
                .catch(error =>{
                    let message = "An error occured while comparingunique strings!";
                    res.redirect(`/user/verified/error=true&message=${message}`);
                })
            }
        }else{
            //user verification record does not exist
            let message = "Account record does not exist or has been verified already. Please Signup or Login!";
            res.redirect(`/user/verified/error=true&message=${message}`);
        }
    })
    .catch((error) =>{
        console.log(error);
        let message = "An error occured while checking for existing user verification record!";
        res.redirect(`/user/verified/error=true&message=${message}`);
    })
})

//Verified page route
router.get("/verified", (req,res) =>{
  res.sendFile(path.join(__dirname, "./../views/verified.html"));
})

//Signin
router.post('/signin', (req,res) => {
    let { email, password } = req.body;
    email = email.trim();
    password = password.trim();

    if (email == "" || password == ""){
        res.json({
            status: "FAILED",
            message: "Please fill in the credentials."
        })
    }else{
        //Check if user exists
        User.find({email})
        .then(data =>{
            if(data.length){
                //user exists

                //check if user is verified

                if (!data[0].verified){
                    res.json({
                        status: "FAILED",
                        message: "Email hasn't been verified yet. Check your inbox."
                    });
                }else{
                    const hashedPassword = data[0].password;
                bcrypt
                .compare(password, hashedPassword)
                .then(result => {
                    if(result){
                        //Password match
                        res.json({
                            status: "SUCCESS",
                            message: "Signin Successful",
                            data: data
                        })
                    }else{
                        res.json({
                            status: "FAILED",
                            message: "Invalid Password entered"
                        })
                    }
                })
                .catch(err =>{
                    res.json({
                        status: "FAILED",
                        message: "An error occured while comparing the passwords!"
                    })
                })
            
            }
                
            }else{
                res.json({
                    status: "FAILED",
                    message: "Invalid credentials entered!"
                })
            }
        })
        .catch(err =>{
            res.json({
                status: "FAILED",
                message: "An error occured while checking for exsisting user!"
            })
        })
    }
});

//send OTP verification Email
const sendOTPVerificationEmail = async ({_id, email}, res) => {
    try {
        const otp = `${Math.floor(1000 + Math.random()*9000)}`;

        //mail options
        const  mailOptions = {
            from: process.env.AUTH_EMAIL,
            to: email,
            subject: "Verify your Email",
            html: `<p>Enter<b>${otp}</b> in the app to verify your email address and complete the authentication process</p><p>This code<b>expires in one hour</b>.</p>`,
        };

        //hash the otp
        const saltRounds = 10;

        const hashedOTP = await bcrypt.hash(otp, saltRounds);
        const newOTPVerification = await new UserOTPVerification({
            UserId: _id,
            otp: hashedOTP,
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000,
        });
        //save OTP records
        await newOTPVerification.save();
        await transporter.sendMail(mailOptions);
        res.json({
            status: "PENDING",
            message: "Verification otp email sent",
            data:{
                userId: _id,
                email,
            },
        });
        
    } catch (error) {
        res.json({
            status: "FAILED",
            message: error.message,
        });
        
    }
};
//verify otp email
router.post("/verifyOTP", async(req, res) =>{
    try{
        let{ userId, otp} = req.body;
        if (!userId || !otp){
            throw Error("OTP field is empty");
        }else{
            const UserOTPVerificationRecords = await UserOTPVerification.find({
                userId,
            });
            if (UserOTPVerificationRecords.length <= 0){
                throw new Error(
                    "Account record does not exist or has been verified already. Please Signup or Login."
                );
            }else{
                //user OTP record exists
                const { expiresAt } = UserOTPVerificationRecords[0];
                const hashedOTP = UserOTPVerificationRecords[0].otp;

                if(expiresAt < Date.now()){
                    //user OTP has expired
                    await UserOTPVerification.deleteMany({ userId });
                    throw new Error("Code has expired. Please request again.");
                }else{
                    const validOTP  =   await bcrypt.compare(otp, hashedOTP);

                    if(!validOTP){
                        throw new Error("Invalid OTP. Check your inbox again.");
                    }else{
                        //success
                        await User.updateOne({_id: userId}, {verified: true});
                        await UserOTPVerification.deleteMany({userId});
                        res.json({
                            status: "VERIFIED",
                            message: "User Email verified successfully",
                        });
                    }


                }
            }
        }
    }catch(error){
        console.log();
        res.json({
            status: "FAILED",
            message: error.message,
        });
    }
});

//resend verification
router.post("/resendOTPVerificationCode", async (req, res) => {
    try{
        let{ userId, email } = req.body;

        if (!userId || !email){
            throw Error("Empty user details are not allowed");
        }else{
            //delete existing records and resend
            await UserOTPVerification.deleteMany({userId});
            sendOTPVerificationEmail({ _id: userId, email}, res)

        }

    }catch(error){
        res.json({
       status: "FAILED",
       message: error.message,
        });
    }
 });


module.exports = router;