import { StatusCodes } from 'http-status-codes'
import {
  ACCESS_TOKEN_SECRET_SIGNATURE,
  JwtProvider
} from '~/providers/JwtProvider'

// Middleware này đảm nhận việc: lấy và xác thực JWT accessToken nhận từ FE có hợp lệ hay không
const isAuthorized = async (req, res, next) => {
  //Cách 1: lấy accessToken trong req cookies từ client gửi - withCredentials trong file authorizeAxios và credentials trong CORS
  const accessTokenFromCookie = req.cookies?.accessToken
  if (!accessTokenFromCookie) {
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: 'Unauthorized! Token not found' })
    return
  }
  //Cách 2:lấy accessToken từ phía FE lưu trong localStorage và gửi lên header authorization
  const accessTokenFromHeader = req.headers.authorization
  if (!accessTokenFromHeader) {
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: 'Unauthorized! Token not found' })
    return
  }

  try {
    // Bước 1: Thực thi xác thực token (verify)
    // verify bằng cookies hoặc header -> chọn 1 cách
    const accessTokenDecoded = await JwtProvider.verifyToken(
      accessTokenFromCookie, // Dùng token theo cách 1
      // accessTokenFromHeader.substring('Bearer '.length), // Dùng token theo cách 2
      ACCESS_TOKEN_SECRET_SIGNATURE
    )
    // Bước 2: Nếu token hợp lệ thì sẽ lưu thông tin đã decode vào req.jwtDecoded để sử dụng cho các tầng xử lý sau -> Lấy đc các giá trị đã decode (email, id user)
    req.jwtDecoded = accessTokenDecoded
    // Bước 3: Cho req đi tiếp
    next()
  } catch (error) {
    //Case 1: Nếu accessToken hết hạn (expired) -> trả về 410 -> Client sử dụng refreshToken
    if (error.message?.includes('jwt expired')) {
      res.status(StatusCodes.GONE).json({ message: 'Please refresh token' })
      return
    }
    //Case 2: Nếu accessToken không hợp lệ (ngoài trường hợp hết hạn token) -> trả lỗi 401 -> FE xử lý Logout/gọi API logout
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: 'Unauthorized! Please login again' })
  }
}

export const authMiddleware = {
  isAuthorized
}
