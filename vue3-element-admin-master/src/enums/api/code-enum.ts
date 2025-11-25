/**
 * API响应码枚举
 */
export const enum ApiCodeEnum {
  /**
   * 成功
   */
  SUCCESS = "00000",
  /**
   * 错误
   */
  ERROR = "B0001",

  /**
   * 访问令牌无效或过期
   */
  ACCESS_TOKEN_INVALID = "A0230",

  /**
   * 未登录或鉴权失败（需要登录）
   */
  AUTH_REQUIRED = "A0201",

  /**
   * 刷新令牌无效或过期
   */
  REFRESH_TOKEN_INVALID = "A0231",

  /**
   * 无权限访问
   */
  PERMISSION_DENIED = "A0301",
}
