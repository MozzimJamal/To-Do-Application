import UserModel from '../models/user_model.js'
import bcrypt from 'bcryptjs'
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js'
import sendEmail from '../config/sendEmail.js' // sendEmail import line 
import generatedAccessToken from '../utils/generatedAccessToken.js' // Access Token import
import generatedRefreshToken from '../utils/generatedRefreshToken.js' // Refresh Token import




export async function registerUserController ( req,res) {

    try {
        const { name, email, password} = req.body

        if(!name || !email || !password){
            return res.status(400).json({
                message : "Provide email, name, password",
                error : true,
                success : false 
            })
        }
        const user = await UserModel.findOne({email})

       if(user){
        return res.json({
            message : "Alredy Register email",
            error : true,
            success : false
        })
       }
    
       const salt = await bcrypt.genSalt(10)
       const hashPassword = await bcrypt.hash(password, salt)

       const payload = {
        name, 
        email, 
        password : hashPassword
       }

       const newUser = new UserModel(payload)
       const save = await newUser.save()

       const verifyEmailUrl =`${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`

       const verifyEmail = await sendEmail({
           sendTo : email,
            subject : "verification from testing ",
            html : verifyEmailTemplate({
                name,
                url : verifyEmailUrl
            })

       })

     return res.json({
        message : "User Register Successfully",
        error : false,
        success : true,
         
        data : save
     })


        
    } catch (error) {
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
        
    }
}




export async function verifyEmailController (req, res){
    try {
        
           const {code} = req.body
           const user  = await UserModel.findOne( {_id : code })

           if(!user){
            return res.status(400).json({
                message : "Invalid code",
                error : true,
                success : false

            }
            )
           }
            const updateUser = await  UserModel.updateOne({ _id : code },{
                verify_email : true 
            }) 
            return res.json({
                message : "Verify Email done",
                success : true,
                error : false 
            })

    } catch (error) {
        return res.status(500).json({ 
            message : error.message || error,
            error : true ,
            success : true
        })
        
    }
}



export async function loginController (req, res){
    try {
        
        const {email, password} = req.body

        if(!email || !password){
            return res.status(400).json({
                message : "Provide email and password",
                error : true,
                success : false
            })
        }

        const user = await UserModel.findOne({email})
        if(!user){
            return res.status(400).json({
                message : "User not Register ",
                error : true,
                success : false
            })
        }

          if(user.status !== "Active"){
            return res.status(400).json({
                message : "Contact to Admin",
                error : true,
                success : false     
            })
          }

        const checkPassword = await bcrypt.compare(password, user.password )

        if(!checkPassword){
            return res.status(400).json({
                message : "Check Your Password",
                error : true,
                success : false
            })
        }
        const accesstoken = await generatedAccessToken(user._id)
        const refreshtoken = await generatedRefreshToken(user._id)
        
         //  Modify 2-6-2025 
           
        const updateUser = await UserModel.findByIdAndUpdate(user?._id,{
            last_login_date : new Date()
        })
          

        const cookieOption ={
            httpOnly : true,
            secure : true,
            sameSite : 'None'
        }

        res.cookie('accesstoken', accesstoken ,cookieOption )
        res.cookie('refreshtoken', refreshtoken ,cookieOption )

        return res.json({
            message : "Login successfully",
            error : false,
            success : true,
            data : {
                accesstoken, refreshtoken
            }
        })



    } catch (error) {
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : true
        })
        
    }
}


export async function logoutController(req, res) {
  try {
    const userId = req.userId;

    if (!userId) {
      return res.status(401).json({
        message: "Unauthorized: user not found",
        error: true,
        success: false,
      });
    }

    const cookiesOption = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
    };

    // clear cookies
    res.clearCookie("accessToken", cookiesOption);
    res.clearCookie("refreshToken", cookiesOption);

    // remove refresh token from DB
    await UserModel.findByIdAndUpdate(userId, { refresh_token: "" });

    return res.json({
      message: "Logout successfully",
      error: false,
      success: true,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message || error,
      error: true,
      success: false,
    });
  }
}
