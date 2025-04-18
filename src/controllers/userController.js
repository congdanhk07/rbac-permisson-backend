import { StatusCodes } from 'http-status-codes'
import ms from 'ms'
import {
  ACCESS_TOKEN_SECRET_SIGNATURE,
  JwtProvider,
  REFRESH_TOKEN_SECRET_SIGNATURE
} from '~/providers/JwtProvider'
// Mock nhanh thông tin user thay vì phải tạo Database rồi query.
const MOCK_DATABASE = {
  USER: {
    ID: 'congdanh-sample-id-12345678',
    EMAIL: 'congdanh.official@gmail.com',
    PASSWORD: 'congdanh@123'
  }
}

const login = async (req, res) => {
  try {
    if (
      req.body.email !== MOCK_DATABASE.USER.EMAIL ||
      req.body.password !== MOCK_DATABASE.USER.PASSWORD
    ) {
      res
        .status(StatusCodes.FORBIDDEN)
        .json({ message: 'Your email or password is incorrect!' })
      return
    }

    // Trường hợp nhập đúng thông tin tài khoản, tạo token và trả về cho phía Client
    //1. Tạo payload (userInfo) để đính kèm trong JWT gửi về Client
    const payload = {
      id: MOCK_DATABASE.USER.ID,
      email: MOCK_DATABASE.USER.EMAIL
    }
    // 2. Tạo ra 2 token: access token và refresh token
    const accessToken = await JwtProvider.generateToken(
      payload,
      ACCESS_TOKEN_SECRET_SIGNATURE,
      // '1h'
      5
    )
    const refreshToken = await JwtProvider.generateToken(
      payload,
      REFRESH_TOKEN_SECRET_SIGNATURE,
      '14 days'
      // 15
    )
    //3 Xử lý trường hợp trả về http only cookie cho Client (Cách 1: Lưu vào cookie)
    // Thời gian sống tối đa của cookie là 14 ngày, chúng ta có thể set là tối đa nhưng thời gian sống của accessToken lưu bên trong là 1h
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: ms('14 days')
    })
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: ms('14 days')
    })

    //4. Trả thông tin user + token về cho Client khi muốn lưu vào local Storage (Cách 2)
    // Chỉ cần chọn 1 trong 2 chứ không cần làm cả 2
    res.status(StatusCodes.OK).json({
      ...payload,
      accessToken,
      refreshToken
    })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const logout = async (req, res) => {
  try {
    // Xóa cookie khi user nhấn logout (đối với HttpOnly)
    res.clearCookie('accessToken')
    res.clearCookie('refreshToken')

    res.status(StatusCodes.OK).json({ message: 'Logout API success!' })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const refreshToken = async (req, res) => {
  try {
    // Case 1: Lấy từ cookies đã đính kèm trong request
    const refreshTokenFromCookie = req.cookies?.refreshToken
    // Case 2: Từ local storage phía FE truyền vào body khi gọi API
    const refreshTokenFromBody = req.body?.refreshToken

    // Verify / giải mã refresh token xem có hợp lệ hay không
    const refreshTokenDecoded = await JwtProvider.verifyToken(
      // refreshTokenFromCookie, // Dùng token theo cách 1
      refreshTokenFromBody, // Dùng token theo cách 2
      REFRESH_TOKEN_SECRET_SIGNATURE
    )
    // Vì chúng ta chỉ lưu những thông tin unique và cố định của user trong token -> lấy luôn từ decode ra -> Tiết kiệm query vào DB để lấy data mới
    // Tạo access Token mới
    const payload = {
      id: refreshTokenDecoded.id,
      email: refreshTokenDecoded.email
    }
    const accessToken = await JwtProvider.generateToken(
      payload,
      ACCESS_TOKEN_SECRET_SIGNATURE,
      // '1h'
      5
    )
    // Res lại cookies (đính kèm lại) accessToken cho case dùng cookies
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: ms('14 days')
    })
    // Trả về accessToken mới cho phía FE khi Fe cần update lại token trong local storage
    res.status(StatusCodes.OK).json({ accessToken })
  } catch (error) {
    res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ message: 'Refresh token API is invalid' })
  }
}

export const userController = {
  login,
  logout,
  refreshToken
}
