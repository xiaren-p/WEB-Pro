<template>
  <div class="profile-container">
    <!-- 错误态 -->
    <el-result v-if="loadError" icon="warning" title="加载失败" :sub-title="loadError">
      <template #extra>
        <el-button type="primary" @click="loadUserProfile">重试</el-button>
      </template>
    </el-result>

    <!-- 加载态 -->
    <el-skeleton v-else-if="loading" :rows="8" animated />

    <!-- 内容态 -->
    <el-row v-else :gutter="20">
      <!-- 左侧个人信息卡片 -->
      <el-col :span="8">
        <el-card class="user-card">
          <div class="user-info">
            <div class="avatar-wrapper">
              <el-avatar :src="userStore.userInfo.avatar" :size="100" />
              <el-button
                type="info"
                class="avatar-edit-btn"
                circle
                :icon="Camera"
                size="small"
                @click="triggerFileUpload"
              />
              <input
                ref="fileInput"
                type="file"
                style="display: none"
                accept="image/*"
                @change="handleFileChange"
              />
            </div>
            <div class="user-name">
              <span class="nickname">{{ userProfile.nickname }}</span>
              <el-icon class="edit-icon" @click="handleOpenDialog(DialogType.ACCOUNT)">
                <Edit />
              </el-icon>
            </div>
            <div class="user-role">{{ userProfile.roleNames }}</div>
          </div>
          <el-divider />
          <div class="user-stats">
            <div class="stat-item">
              <div class="stat-value">0</div>
              <div class="stat-label">待办</div>
            </div>
            <div class="stat-item">
              <div class="stat-value">0</div>
              <div class="stat-label">消息</div>
            </div>
            <div class="stat-item">
              <div class="stat-value">0</div>
              <div class="stat-label">通知</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <!-- 右侧信息卡片 -->
      <el-col :span="16">
        <el-card class="info-card">
          <template #header>
            <div class="card-header">
              <span>账号信息</span>
            </div>
          </template>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="用户名">
              {{ userProfile.username }}
              <el-icon v-if="userProfile.gender === 1" class="gender-icon male">
                <Male />
              </el-icon>
              <el-icon v-else class="gender-icon female">
                <Female />
              </el-icon>
            </el-descriptions-item>
            <el-descriptions-item label="手机号码">
              {{ userProfile.mobile || "未绑定" }}
              <el-button
                v-if="userProfile.mobile"
                type="primary"
                link
                @click="() => handleOpenDialog(DialogType.MOBILE)"
              >
                更换
              </el-button>
              <el-button
                v-else
                type="primary"
                link
                @click="() => handleOpenDialog(DialogType.MOBILE)"
              >
                绑定
              </el-button>
            </el-descriptions-item>
            <el-descriptions-item label="邮箱">
              {{ userProfile.email || "未绑定" }}
              <el-button
                v-if="userProfile.email"
                type="primary"
                link
                @click="() => handleOpenDialog(DialogType.EMAIL)"
              >
                更换
              </el-button>
              <el-button
                v-else
                type="primary"
                link
                @click="() => handleOpenDialog(DialogType.EMAIL)"
              >
                绑定
              </el-button>
            </el-descriptions-item>
            <el-descriptions-item label="部门">
              {{ userProfile.deptName }}
            </el-descriptions-item>
            <el-descriptions-item label="创建时间">
              {{ userProfile.createTime }}
            </el-descriptions-item>
          </el-descriptions>
        </el-card>

        <el-card class="security-card">
          <template #header>
            <div class="card-header">
              <span>安全设置</span>
            </div>
          </template>
          <div class="security-item">
            <div class="security-info">
              <div class="security-title">账户密码</div>
              <div class="security-desc">定期修改密码有助于保护账户安全</div>
            </div>
            <el-button type="primary" link @click="() => handleOpenDialog(DialogType.PASSWORD)">
              修改
            </el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 弹窗 -->
    <el-dialog v-model="dialog.visible" :title="dialog.title" :width="500">
      <!-- 账号资料 -->
      <el-form
        v-if="dialog.type === DialogType.ACCOUNT"
        ref="userProfileFormRef"
        :model="userProfileForm"
        :label-width="100"
      >
        <el-form-item label="昵称">
          <el-input v-model="userProfileForm.nickname" />
        </el-form-item>
        <el-form-item label="性别">
          <Dict v-model="userProfileForm.gender" code="gender" />
        </el-form-item>
      </el-form>

      <!-- 修改密码 -->
      <el-form
        v-if="dialog.type === DialogType.PASSWORD"
        ref="passwordChangeFormRef"
        :model="passwordChangeForm"
        :rules="passwordChangeRules"
        :label-width="100"
      >
        <el-form-item label="原密码" prop="oldPassword">
          <el-input v-model="passwordChangeForm.oldPassword" type="password" show-password />
        </el-form-item>
        <el-form-item label="新密码" prop="newPassword">
          <el-input v-model="passwordChangeForm.newPassword" type="password" show-password />
        </el-form-item>
        <el-form-item label="确认密码" prop="confirmPassword">
          <el-input v-model="passwordChangeForm.confirmPassword" type="password" show-password />
        </el-form-item>
      </el-form>

      <!-- 绑定手机 -->
      <el-form
        v-else-if="dialog.type === DialogType.MOBILE"
        ref="mobileBindingFormRef"
        :model="mobileUpdateForm"
        :rules="mobileBindingRules"
        :label-width="100"
      >
        <el-form-item label="手机号码" prop="mobile">
          <el-input v-model="mobileUpdateForm.mobile" style="width: 250px" />
        </el-form-item>
        <el-form-item label="验证码" prop="code">
          <el-input v-model="mobileUpdateForm.code" style="width: 250px">
            <template #append>
              <el-button :disabled="mobileCountdown > 0" @click="handleSendMobileCode">
                {{ mobileCountdown > 0 ? `${mobileCountdown}s后重新发送` : "发送验证码" }}
              </el-button>
            </template>
          </el-input>
        </el-form-item>
      </el-form>

      <!-- 绑定邮箱 -->
      <el-form
        v-else-if="dialog.type === DialogType.EMAIL"
        ref="emailBindingFormRef"
        :model="emailUpdateForm"
        :rules="emailBindingRules"
        :label-width="100"
      >
        <el-form-item label="邮箱" prop="email">
          <el-input v-model="emailUpdateForm.email" style="width: 250px" />
        </el-form-item>
        <el-form-item label="验证码" prop="code">
          <el-input v-model="emailUpdateForm.code" style="width: 250px">
            <template #append>
              <el-button :disabled="emailCountdown > 0" @click="handleSendEmailCode">
                {{ emailCountdown > 0 ? `${emailCountdown}s后重新发送` : "发送验证码" }}
              </el-button>
            </template>
          </el-input>
        </el-form-item>
      </el-form>

      <template #footer>
        <span class="dialog-footer">
          <el-button @click="handleCancel">取消</el-button>
          <el-button type="primary" @click="handleSubmit">确定</el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script lang="ts" setup>
import { UserAPI } from "@/backend";
import { useUserStoreHook } from "@/store";
import { Camera, Edit, Male, Female } from "@element-plus/icons-vue";
import { ref, reactive, onMounted, computed } from "vue";
import { ElLoading, ElMessageBox, ElMessage } from "element-plus";

// 本地类型定义（适配 consolidated backend.ts）
interface UserProfileVO {
  id?: string;
  username?: string;
  nickname?: string;
  avatar?: string;
  email?: string;
  mobile?: string;
  gender?: number;
  deptName?: string;
  roleNames?: string;
  createTime?: string;
}
interface PasswordChangeForm {
  oldPassword?: string;
  newPassword?: string;
  confirmPassword?: string;
}
interface MobileUpdateForm {
  mobile?: string;
  code?: string;
}
interface EmailUpdateForm {
  email?: string;
  code?: string;
}
interface UserProfileForm {
  id?: string;
  nickname?: string;
  gender?: number;
}

const userStore = useUserStoreHook();
// 计算 seafile 缓存标志为本地布尔，避免直接比较可能的 ref/object
const seafileCached = computed(() => {
  try {
    return !!(userStore && (userStore as any).seafileCached);
  } catch {
    return false;
  }
});
const userProfile = ref<UserProfileVO>({});
const loading = ref(true);
const loadError = ref<string | null>(null);

// file input 在下方与上传逻辑一起声明

const enum DialogType {
  ACCOUNT = "account",
  PASSWORD = "password",
  MOBILE = "mobile",
  EMAIL = "email",
}

const dialog = reactive({
  visible: false,
  title: "",
  type: "" as DialogType, // 修改账号资料,修改密码、绑定手机、绑定邮箱
});
const userProfileFormRef = ref();
const passwordChangeFormRef = ref();
const mobileBindingFormRef = ref();
const emailBindingFormRef = ref();

const userProfileForm = reactive<UserProfileForm>({});
const passwordChangeForm = reactive<PasswordChangeForm>({});
const mobileUpdateForm = reactive<MobileUpdateForm>({});
const emailUpdateForm = reactive<EmailUpdateForm>({});

const mobileCountdown = ref(0);
const mobileTimer = ref();

const emailCountdown = ref(0);
const emailTimer = ref();

// 修改密码校验规则
const passwordChangeRules = {
  oldPassword: [{ required: true, message: "请输入原密码", trigger: "blur" }],
  newPassword: [{ required: true, message: "请输入新密码", trigger: "blur" }],
  confirmPassword: [{ required: true, message: "请再次输入新密码", trigger: "blur" }],
};

// 手机号校验规则
const mobileBindingRules = {
  mobile: [
    { required: true, message: "请输入手机号", trigger: "blur" },
    {
      pattern: /^1[3|4|5|6|7|8|9][0-9]\d{8}$/,
      message: "请输入正确的手机号码",
      trigger: "blur",
    },
  ],
  code: [{ required: true, message: "请输入验证码", trigger: "blur" }],
};

// 邮箱校验规则
const emailBindingRules = {
  email: [
    { required: true, message: "请输入邮箱", trigger: "blur" },
    {
      pattern: /\w[-\w.+]*@([A-Za-z0-9][-A-Za-z0-9]+\.)+[A-Za-z]{2,14}/,
      message: "请输入正确的邮箱地址",
      trigger: "blur",
    },
  ],
  code: [{ required: true, message: "请输入验证码", trigger: "blur" }],
};

/**
 * 打开弹窗
 * @param type 弹窗类型 ACCOUNT: 账号资料 PASSWORD: 修改密码 MOBILE: 绑定手机 EMAIL: 绑定邮箱
 */
const handleOpenDialog = (type: DialogType) => {
  dialog.type = type;
  dialog.visible = true;
  switch (type) {
    case DialogType.ACCOUNT:
      dialog.title = "账号资料";
      // 初始化表单数据
      userProfileForm.id = userProfile.value.id;
      userProfileForm.nickname = userProfile.value.nickname;
      userProfileForm.gender = userProfile.value.gender;
      break;
    case DialogType.PASSWORD:
      dialog.title = "修改密码";
      break;
    case DialogType.MOBILE:
      dialog.title = "绑定手机";
      break;
    case DialogType.EMAIL:
      dialog.title = "绑定邮箱";
      break;
  }
};

/**
 * 发送手机验证码
 */
function handleSendMobileCode() {
  if (!mobileUpdateForm.mobile) {
    ElMessage.error("请输入手机号");
    return;
  }
  // 验证手机号格式
  const reg = /^1[3-9]\d{9}$/;
  if (!reg.test(mobileUpdateForm.mobile)) {
    ElMessage.error("手机号格式不正确");
    return;
  }
  // 发送短信验证码
  UserAPI.sendMobileCode(mobileUpdateForm.mobile).then(() => {
    ElMessage.success("验证码发送成功");

    // 倒计时 60s 重新发送
    mobileCountdown.value = 60;
    mobileTimer.value = setInterval(() => {
      if (mobileCountdown.value > 0) {
        mobileCountdown.value -= 1;
      } else {
        clearInterval(mobileTimer.value!);
      }
    }, 1000);
  });
}

/**
 * 发送邮箱验证码
 */
function handleSendEmailCode() {
  if (!emailUpdateForm.email) {
    ElMessage.error("请输入邮箱");
    return;
  }
  // 验证邮箱格式
  const reg = /\w[-\w.+]*@([A-Za-z0-9][-A-Za-z0-9]+\.)+[A-Za-z]{2,14}/;
  if (!reg.test(emailUpdateForm.email)) {
    ElMessage.error("邮箱格式不正确");
    return;
  }

  // 发送邮箱验证码
  UserAPI.sendEmailCode(emailUpdateForm.email).then(() => {
    ElMessage.success("验证码发送成功");
    // 倒计时 60s 重新发送
    emailCountdown.value = 60;
    emailTimer.value = setInterval(() => {
      if (emailCountdown.value > 0) {
        emailCountdown.value -= 1;
      } else {
        clearInterval(emailTimer.value!);
      }
    }, 1000);
  });
}

/**
 * 提交表单
 */
const handleSubmit = async () => {
  if (dialog.type === DialogType.ACCOUNT) {
    try {
      // 如果后端在登录时已告知 seafile token 在服务器端缓存，则
      // 前端不再强制提示输入密码；仅当缓存不存在时再弹出提示。
      let pwd = "";
      // 明确将 seafileCached 转为布尔值以避免 ref/未定义导致的误判
      console.debug("[profile] seafileCached (before profile submit):", seafileCached.value);
      if (!seafileCached.value) {
        try {
          const promptRes: any = await ElMessageBox.prompt(
            "请输入当前登录密码以同步云端昵称（可留空以跳过同步）",
            "验证密码",
            {
              inputType: "password",
              confirmButtonText: "确定",
              cancelButtonText: "取消",
            }
          );
          pwd = promptRes && promptRes.value ? promptRes.value : "";
        } catch {
          // 取消输入：继续本地更新但不进行 Seafile 同步
          pwd = "";
        }
      }
      const payload: any = { ...userProfileForm };
      if (pwd) payload.cloudPassword = pwd;
      const resp: any = await UserAPI.updateProfile(payload);
      ElMessage.success("账号资料修改成功");
      dialog.visible = false;
      loadUserProfile();
      const seafileProfileSync =
        resp?.seafileProfileSync || (resp && resp.data && resp.data.seafileProfileSync);
      // 弹窗展示云端同步结果（若有）或提示未执行同步
      let content = "";
      let boxType: any = "info";
      if (seafileProfileSync) {
        content = `云端同步结果：${seafileProfileSync.success ? "成功" : "失败"}\n${seafileProfileSync.msg || ""}`;
        boxType = seafileProfileSync.success ? "success" : "warning";
      } else {
        content = "未执行云端同步（未提供密码或未配置 Seafile 站点）";
        boxType = "info";
      }
      // 使用消息提示替代模态对话框
      if (boxType === "success") {
        ElMessage.success(content);
      } else if (boxType === "warning") {
        ElMessage.warning(content);
      } else {
        ElMessage.info(content);
      }
    } catch (err: any) {
      ElMessage.error(err?.message || "更新失败");
    }
  } else if (dialog.type === DialogType.PASSWORD) {
    if (passwordChangeForm.newPassword !== passwordChangeForm.confirmPassword) {
      ElMessage.error("两次输入的密码不一致");
      return;
    }
    try {
      const resp: any = await UserAPI.changePassword(passwordChangeForm);
      const seafileSync = resp?.seafileSync || (resp && resp.data && resp.data.seafileSync);
      // 先告知本地修改成功
      ElMessage.success("密码修改成功");
      dialog.visible = false;
      // 若后端返回云端同步结果，展示给用户
      if (seafileSync) {
        const content = `云端同步结果：${seafileSync.success ? "成功" : "失败"}\n${seafileSync.msg || ""}`;
        if (seafileSync.success) {
          ElMessage.success(content);
        } else {
          ElMessage.warning(content);
        }
      }
    } catch (err: any) {
      ElMessage.error(err?.message || "修改密码失败");
    }
  } else if (dialog.type === DialogType.MOBILE) {
    UserAPI.bindOrChangeMobile(mobileUpdateForm).then(() => {
      ElMessage.success("手机号绑定成功");
      dialog.visible = false;
      loadUserProfile();
    });
  } else if (dialog.type === DialogType.EMAIL) {
    UserAPI.bindOrChangeEmail(emailUpdateForm).then(() => {
      ElMessage.success("邮箱绑定成功");
      dialog.visible = false;
      loadUserProfile();
    });
  }
};

/**
 * 取消
 */
const handleCancel = () => {
  dialog.visible = false;
  if (dialog.type === DialogType.ACCOUNT) {
    userProfileFormRef.value?.resetFields();
  } else if (dialog.type === DialogType.PASSWORD) {
    passwordChangeFormRef.value?.resetFields();
  } else if (dialog.type === DialogType.MOBILE) {
    mobileBindingFormRef.value?.resetFields();
  } else if (dialog.type === DialogType.EMAIL) {
    emailBindingFormRef.value?.resetFields();
  }
};

const fileInput = ref<HTMLInputElement | null>(null);
const uploading = ref(false);

const triggerFileUpload = () => {
  if (uploading.value) return;
  fileInput.value?.click();
};

const handleFileChange = async (e: Event) => {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  if (!file.type.startsWith("image/")) {
    ElMessage.error("请选择图片文件");
    input.value = "";
    return;
  }
  if (file.size > 2 * 1024 * 1024) {
    ElMessage.error("图片大小不能超过 2MB");
    input.value = "";
    return;
  }
  let loadingSvc: any = null;
  try {
    // 如果后端已在登录时告知服务器已缓存 Seafile token，优先不弹密码提示
    let pwd = "";
    console.debug("[profile] seafileCached (before avatar upload):", seafileCached.value);
    if (!seafileCached.value) {
      try {
        const promptRes: any = await ElMessageBox.prompt(
          "请输入当前登录密码以同步 Seafile（必填）",
          "验证密码",
          {
            inputType: "password",
            confirmButtonText: "确定",
            cancelButtonText: "取消",
          }
        );
        pwd = promptRes && promptRes.value ? promptRes.value : "";
      } catch {
        // 用户取消输入，直接终止上传
        return;
      }
      if (!pwd) {
        ElMessage.error("必须输入当前登录密码以继续同步");
        return;
      }
    }
    uploading.value = true;
    loadingSvc = ElLoading.service({ text: "上传中...", background: "rgba(0,0,0,0.3)" });
    const res: any = await UserAPI.uploadAvatar(file, pwd || undefined);
    const url = res?.url || (res && (res as any).data && (res as any).data.url) || "";
    const seafileAvatarSync =
      res?.seafileAvatarSync || (res && (res as any).data && (res as any).data.seafileAvatarSync);
    // 同步更新 Pinia store，避免额外 profile 请求
    if (url) userStore.userInfo.avatar = url;
    await UserAPI.updateProfile({ avatar: url });
    // 本地 userProfile 也立即更新
    userProfile.value.avatar = url;
    ElMessage.success("头像已更新");
    // 若后端返回 Seafile 同步结果，则展示给用户
    if (seafileAvatarSync) {
      if (seafileAvatarSync.success) {
        ElMessage.success("云端头像同步成功");
      } else {
        ElMessage.warning(`云端头像同步失败：${seafileAvatarSync.msg || "未知错误"}`);
      }
    }
  } catch (err: any) {
    ElMessage.error(err?.message || "上传失败");
  } finally {
    uploading.value = false;
    input.value = "";
    if (loadingSvc) {
      try {
        loadingSvc.close();
      } catch {
        // ignore
      }
    }
  }
};

/** 加载用户信息 */
const preloadFromStore = () => {
  // 先用已登录的简要信息填充，提升感知速度
  const basic = userStore.userInfo || ({} as any);
  if (basic && (basic.username || basic.nickname)) {
    userProfile.value.username = basic.username;
    userProfile.value.nickname = basic.nickname;
    userProfile.value.avatar = basic.avatar;
  }
};

const loadUserProfile = async () => {
  loadError.value = null;
  loading.value = true;
  try {
    const data = await Promise.race([
      UserAPI.getProfile(),
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 8000)),
    ]);
    userProfile.value = data as any;
  } catch (err: any) {
    if (err?.message === "timeout") {
      loadError.value = "获取资料超时，请刷新重试";
    } else {
      loadError.value = err?.message || "加载失败";
    }
  } finally {
    loading.value = false;
  }
};

onMounted(async () => {
  if (mobileTimer.value) {
    clearInterval(mobileTimer.value);
  }
  if (emailTimer.value) {
    clearInterval(emailTimer.value);
  }
  // 预填用户基本信息，随后拉取完整资料
  preloadFromStore();
  await loadUserProfile();
});
</script>

<style lang="scss" scoped>
.profile-container {
  min-height: calc(100vh - 84px);
  padding: 20px;
  background: var(--el-fill-color-blank);
}

.user-card {
  .user-info {
    padding: 20px 0;
    text-align: center;

    .avatar-wrapper {
      position: relative;
      display: inline-block;
      margin-bottom: 16px;

      .avatar-edit-btn {
        position: absolute;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.5);
        border: none;
        transition: all 0.3s ease;

        &:hover {
          background: rgba(0, 0, 0, 0.7);
        }
      }
    }

    .user-name {
      margin-bottom: 8px;

      .nickname {
        font-size: 18px;
        font-weight: 600;
        color: var(--el-text-color-primary);
      }

      .edit-icon {
        margin-left: 8px;
        color: var(--el-text-color-secondary);
        cursor: pointer;
        transition: all 0.3s ease;

        &:hover {
          color: var(--el-color-primary);
        }
      }
    }

    .user-role {
      font-size: 14px;
      color: var(--el-text-color-secondary);
    }
  }

  .user-stats {
    display: flex;
    justify-content: space-around;
    padding: 16px 0;

    .stat-item {
      text-align: center;

      .stat-value {
        font-size: 20px;
        font-weight: 600;
        color: var(--el-text-color-primary);
      }

      .stat-label {
        margin-top: 4px;
        font-size: 12px;
        color: var(--el-text-color-secondary);
      }
    }
  }
}

.info-card,
.security-card {
  margin-bottom: 20px;

  .card-header {
    font-size: 16px;
    font-weight: 600;
    color: var(--el-text-color-primary);
  }
}

.security-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;

  .security-info {
    .security-title {
      margin-bottom: 4px;
      font-size: 16px;
      font-weight: 500;
      color: var(--el-text-color-primary);
    }

    .security-desc {
      font-size: 14px;
      color: var(--el-text-color-secondary);
    }
  }
}

.el-descriptions {
  .el-descriptions__label {
    font-weight: 500;
    color: var(--el-text-color-regular);
  }

  .el-descriptions__content {
    color: var(--el-text-color-primary);
  }

  .gender-icon {
    margin-left: 8px;
    font-size: 16px;

    &.male {
      color: #409eff;
    }

    &.female {
      color: #f56c6c;
    }
  }
}

.el-dialog {
  .el-dialog__header {
    padding: 20px;
    margin: 0;
    border-bottom: 1px solid var(--el-border-color-light);
  }

  .el-dialog__body {
    padding: 30px 20px;
  }

  .el-dialog__footer {
    padding: 20px;
    border-top: 1px solid var(--el-border-color-light);
  }
}

// 响应式适配
@media (max-width: 768px) {
  .profile-container {
    padding: 10px;
  }

  .el-col {
    width: 100%;
  }
}
</style>
