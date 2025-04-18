import JWT from 'jsonwebtoken'

/*
Function tạo mới một token cần 3 tham số đầu vào
userInfo: Những thông tin muốn đính kèm vào token
secrectSignature: Chữ kí bí mật (String ngẫu nhiên)
tokenLife: Thời gian sống của token
*/
const generateToken = async (userInfo, secrectSignature, tokenLife) => {
  try {
    return JWT.sign(userInfo, secrectSignature, {
      algorithm: 'HS256',
      expiresIn: tokenLife
    })
  } catch (error) {
    throw new Error(error)
  }
}

// Check token có hợp lệ hay không  -> Token đc tạo ra có đúng với secretSignature hay không
const verifyToken = (token, secrectSignature) => {
  try {
    return JWT.verify(token, secrectSignature)
  } catch (error) {
    throw new Error(error)
  }
}

// 2 cái chữ ký bí mật quan trọng trong dự án. Dành cho JWT - Jsonwebtokens
// Lưu ý phải lưu vào biến môi trường ENV trong thực tế cho bảo mật.
export const ACCESS_TOKEN_SECRET_SIGNATURE = 'KBgJwUETt4HeVD05WaXXI9V3JnwCVP'
export const REFRESH_TOKEN_SECRET_SIGNATURE = 'fcCjhnpeopVn2Hg1jG75MUi62051yL'
export const JwtProvider = {
  generateToken,
  verifyToken
}
