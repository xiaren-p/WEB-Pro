<!-- 用户管理 -->
<template>
  <div class="app-container">
    <el-row :gutter="20">
      <!-- 部门树 -->
      <el-col :lg="4" :xs="24" class="mb-[12px]">
        <DeptTree v-model="queryParams.deptId" @node-click="handleQuery" />
      </el-col>

      <!-- 用户列表 -->
      <el-col :lg="20" :xs="24">
        <!-- 搜索区域 -->
        <div class="search-container">
          <el-form ref="queryFormRef" :model="queryParams" :inline="true" label-width="auto">
            <el-form-item label="关键字" prop="keywords">
              <el-input
                v-model="queryParams.keywords"
                placeholder="用户名/昵称/手机号"
                clearable
                @keyup.enter="handleQuery"
              />
            </el-form-item>

            <el-form-item label="状态" prop="status">
              <el-select
                v-model="queryParams.status"
                placeholder="全部"
                clearable
                style="width: 100px"
              >
                <el-option label="正常" :value="1" />
                <el-option label="禁用" :value="0" />
              </el-select>
            </el-form-item>

            <el-form-item label="创建时间">
              <el-date-picker
                v-model="queryParams.createTime"
                :editable="false"
                type="daterange"
                range-separator="~"
                start-placeholder="开始时间"
                end-placeholder="截止时间"
                value-format="YYYY-MM-DD"
              />
            </el-form-item>

            <el-form-item class="search-buttons">
              <el-button type="primary" icon="search" @click="handleQuery">搜索</el-button>
              <el-button icon="refresh" @click="handleResetQuery">重置</el-button>
            </el-form-item>
          </el-form>
        </div>

        <el-card shadow="hover" class="data-table">
          <div class="data-table__toolbar">
            <div class="data-table__toolbar--actions">
              <el-button
                v-hasPerm="['sys:user:add']"
                type="success"
                icon="plus"
                @click="handleOpenDialog()"
              >
                新增
              </el-button>
              <el-button
                v-hasPerm="'sys:user:delete'"
                type="danger"
                icon="delete"
                :disabled="selectIds.length === 0"
                @click="handleDelete()"
              >
                删除
              </el-button>
              <el-button
                v-hasPerm="'sys:user:add'"
                type="primary"
                icon="plus"
                :disabled="selectIds.length === 0"
                @click="handleCreateCloudUser"
              >
                创建 cloud 用户
              </el-button>
            </div>
            <div class="data-table__toolbar--tools">
              <el-button
                v-hasPerm="'sys:user:import'"
                icon="upload"
                @click="handleOpenImportDialog"
              >
                导入
              </el-button>

              <el-button v-hasPerm="'sys:user:export'" icon="download" @click="handleExport">
                导出
              </el-button>
            </div>
          </div>

          <el-table
            v-loading="loading"
            :data="pageData"
            border
            stripe
            highlight-current-row
            class="data-table__content"
            @selection-change="handleSelectionChange"
          >
            <el-table-column type="selection" width="50" align="center" />
            <el-table-column label="用户名" prop="username" />
            } catch { // ignore }
            <el-table-column label="昵称" width="150" align="center" prop="nickname" />
            <el-table-column label="性别" width="100" align="center">
              <template #default="scope">
                <DictLabel v-model="scope.row.gender" code="gender" />
              </template>
            </el-table-column>
            <el-table-column label="部门" width="120" align="center" prop="deptName" />
            <el-table-column label="手机号码" align="center" prop="mobile" width="120" />
            <el-table-column label="邮箱" align="center" prop="email" width="160" />
            <el-table-column label="状态" align="center" prop="status" width="80">
              <template #default="scope">
                <el-tag :type="scope.row.status == 1 ? 'success' : 'info'">
                  {{ scope.row.status == 1 ? "正常" : "禁用" }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="创建时间" align="center" prop="createTime" width="150" />
            <el-table-column label="操作" fixed="right" width="220">
              <template #default="scope">
                <el-button
                  v-hasPerm="'sys:user:reset-password'"
                  type="primary"
                  icon="RefreshLeft"
                  size="small"
                  link
                  @click="hancleResetPassword(scope.row)"
                >
                  重置密码
                </el-button>
                <el-button
                  v-hasPerm="'sys:user:edit'"
                  type="primary"
                  icon="edit"
                  link
                  size="small"
                  @click="handleOpenDialog(scope.row.id)"
                >
                  编辑
                </el-button>
                <el-button
                  v-hasPerm="'sys:user:delete'"
                  type="danger"
                  icon="delete"
                  link
                  size="small"
                  @click="handleDelete(scope.row.id)"
                >
                  删除
                </el-button>
              </template>
            </el-table-column>
          </el-table>

          <pagination
            v-if="total > 0"
            v-model:total="total"
            v-model:page="queryParams.pageNum"
            v-model:limit="queryParams.pageSize"
            @pagination="fetchData"
          />
        </el-card>
      </el-col>
    </el-row>

    <!-- 用户表单 -->
    <el-drawer
      v-model="dialog.visible"
      :title="dialog.title"
      append-to-body
      :size="drawerSize"
      @close="handleCloseDialog"
    >
      <el-form ref="userFormRef" :model="formData" :rules="rules" label-width="80px">
        <el-form-item label="用户名" prop="username">
          <el-input
            v-model="formData.username"
            :readonly="!!formData.id"
            placeholder="请输入用户名"
          />
        </el-form-item>

        <el-form-item v-if="!formData.id" label="密码" prop="password">
          <el-input
            v-model="formData.password"
            type="password"
            show-password
            placeholder="至少6位密码"
          />
        </el-form-item>

        <el-form-item label="用户昵称" prop="nickname">
          <el-input v-model="formData.nickname" placeholder="请输入用户昵称" />
        </el-form-item>

        <el-form-item label="所属部门" prop="deptId">
          <el-tree-select
            v-model="formData.deptId"
            placeholder="请选择所属部门"
            :data="deptOptions"
            filterable
            check-strictly
            :render-after-expand="false"
          />
        </el-form-item>

        <el-form-item label="性别" prop="gender">
          <Dict v-model="formData.gender" code="gender" type="radio" />
        </el-form-item>

        <el-form-item label="角色" prop="roleIds">
          <el-select v-model="formData.roleIds" multiple placeholder="请选择">
            <el-option
              v-for="item in roleOptions"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>

        <el-form-item label="手机号码" prop="mobile">
          <el-input v-model="formData.mobile" placeholder="请输入手机号码" maxlength="11" />
        </el-form-item>

        <el-form-item label="邮箱" prop="email">
          <el-input v-model="formData.email" placeholder="请输入邮箱" maxlength="50" />
        </el-form-item>

        <el-form-item label="账号状态" prop="status">
          <el-switch
            v-model="formData.status"
            inline-prompt
            active-text="正常"
            inactive-text="禁用"
            :active-value="1"
            :inactive-value="0"
          />
        </el-form-item>

        <el-form-item v-if="!formData.id" prop="createCloud">
          <template #label>
            <span style="white-space: nowrap; font-size: 12px">创建cloud账号</span>
          </template>
          <el-radio-group v-model="formData.createCloud">
            <el-radio :label="true">是</el-radio>
            <el-radio :label="false">否</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>

      <template #footer>
        <div class="dialog-footer">
          <el-button type="primary" @click="handleSubmit">确 定</el-button>
          <el-button @click="handleCloseDialog">取 消</el-button>
        </div>
      </template>
    </el-drawer>

    <!-- 用户导入 -->
    <UserImport v-model="importDialogVisible" @import-success="handleQuery()" />
  </div>
</template>

<script setup lang="ts">
import { useAppStore } from "@/store/modules/app-store";
import { DeviceEnum } from "@/enums/settings/device-enum";

import { UserAPI, type UserPageQuery, type UserPageVO, DeptAPI, RoleAPI } from "@/backend";

import DeptTree from "./components/DeptTree.vue";
import UserImport from "./components/UserImport.vue";
import { useUserStore } from "@/store";
const userStore = useUserStore();
defineOptions({
  name: "User",
  inheritAttrs: false,
});

const appStore = useAppStore();

const queryFormRef = ref();
const userFormRef = ref();

const queryParams = reactive<UserPageQuery>({
  pageNum: 1,
  pageSize: 10,
});

const pageData = ref<UserPageVO[]>();
const total = ref(0);
const loading = ref(false);

const dialog = reactive({
  visible: false,
  title: "新增用户",
});
const drawerSize = computed(() => (appStore.device === DeviceEnum.DESKTOP ? "600px" : "90%"));

const formData = reactive<any>({
  status: 1,
  // 是否在 Seafile 上同时创建 cloud 账号
  createCloud: false,
});
const rules = reactive({
  username: [{ required: true, message: "用户名不能为空", trigger: "blur" }],
  password: [
    { required: true, message: "密码不能为空", trigger: "blur" },
    { min: 6, message: "密码至少6位", trigger: "blur" },
  ],
  nickname: [{ required: true, message: "用户昵称不能为空", trigger: "blur" }],
  deptId: [{ required: true, message: "所属部门不能为空", trigger: "blur" }],
  roleIds: [{ required: true, message: "用户角色不能为空", trigger: "blur" }],
  email: [
    { required: true, message: "邮箱不能为空", trigger: "blur" },
    {
      pattern: /\w[-\w.+]*@([A-Za-z0-9][-A-Za-z0-9]+\.)+[A-Za-z]{2,14}/,
      message: "请输入正确的邮箱地址",
      trigger: "blur",
    },
  ],
  mobile: [
    {
      pattern: /^1[3|4|5|6|7|8|9][0-9]\d{8}$/,
      message: "请输入正确的手机号码",
      trigger: "blur",
    },
  ],
});

// 选中的用户ID
const selectIds = ref<number[]>([]);
// 部门下拉数据源
const deptOptions = ref<OptionType[]>();
// 角色下拉数据源
const roleOptions = ref<OptionType[]>();
// 导入弹窗显示状态
const importDialogVisible = ref(false);

// 获取数据
async function fetchData() {
  loading.value = true;
  try {
    const data = await UserAPI.getPage(queryParams);
    pageData.value = data.list;
    total.value = data.total;
  } finally {
    loading.value = false;
  }
}

// 查询（重置页码后获取数据）
function handleQuery() {
  queryParams.pageNum = 1;
  fetchData();
}

// 重置查询
function handleResetQuery() {
  queryFormRef.value.resetFields();
  queryParams.pageNum = 1;
  queryParams.deptId = undefined;
  queryParams.createTime = undefined;
  fetchData();
}

// 选中项发生变化
function handleSelectionChange(selection: any[]) {
  selectIds.value = selection.map((item) => item.id);
}

// 重置密码
function hancleResetPassword(row: UserPageVO) {
  ElMessageBox.prompt("请输入用户【" + row.username + "】的新密码", "重置密码", {
    confirmButtonText: "确定",
    cancelButtonText: "取消",
  }).then(
    ({ value }) => {
      if (!value || value.length < 6) {
        ElMessage.warning("密码至少需要6位字符，请重新输入");
        return false;
      }
      UserAPI.resetPassword(row.id, value)
        .then((resp: any) => {
          const data = resp?.data || resp || {};
          ElMessage.success("密码重置成功，新密码是：" + value);
          // 若后端返回 Seafile 同步结果，则展示给用户
          if (data.seafileSync) {
            const s = data.seafileSync;
            if (s.success) {
              ElMessage.success("云端密码同步成功");
            } else {
              ElMessageBox.alert(`云端密码同步失败：${s.msg || "未知错误"}`, "云端同步结果", {
                type: "warning",
                confirmButtonText: "确定",
              });
            }
          }
        })
        .catch(() => {
          ElMessage.error("重置密码失败，请稍后重试");
        });
    },
    () => {
      ElMessage.info("已取消重置密码");
    }
  );
}

/**
 * 打开弹窗
 *
 * @param id 用户ID
 */
async function handleOpenDialog(id?: string) {
  dialog.visible = true;
  // 加载角色下拉数据源
  roleOptions.value = await RoleAPI.getOptions();
  // 加载部门下拉数据源
  deptOptions.value = await DeptAPI.getOptions();

  if (id) {
    dialog.title = "修改用户";
    UserAPI.getFormData(id).then((data) => {
      Object.assign(formData, { ...data });
    });
  } else {
    dialog.title = "新增用户";
    formData.password = undefined;
  }
}

// 关闭弹窗
function handleCloseDialog() {
  dialog.visible = false;
  userFormRef.value.resetFields();
  userFormRef.value.clearValidate();

  formData.id = undefined;
  formData.status = 1;
  formData.password = undefined;
}

// 提交用户表单（防抖）
const handleSubmit = useDebounceFn(() => {
  userFormRef.value.validate((valid: boolean) => {
    if (valid) {
      const userId = formData.id;
      loading.value = true;
      if (userId) {
        UserAPI.update(userId, formData)
          .then((resp: any) => {
            const data = resp?.data || resp || {};
            // 显示常规成功提示
            ElMessage.success("修改用户成功");
            // 若后端返回 Seafile 同步结果，展示给用户
            if (data.seafileSync) {
              const s = data.seafileSync;
              if (s.success) {
                ElMessage.success("云端账户同步成功");
              } else {
                ElMessageBox.alert(`云端账户同步失败：${s.msg || "未知错误"}`, "云端同步结果", {
                  type: "warning",
                  confirmButtonText: "确定",
                });
              }
            }
            handleCloseDialog();
            handleResetQuery();
          })
          .finally(() => (loading.value = false));
      } else {
        const payload = { ...formData };
        if (!payload.password || payload.password.length < 6) {
          ElMessage.warning("请输入至少6位密码");
          loading.value = false;
          return;
        }
        UserAPI.create(payload)
          .then(async (res: any) => {
            ElMessage.success("新增用户成功");
            // 如果勾选了同时创建 cloud 账号，调用后端代理创建
            try {
              if (payload.createCloud) {
                const userId = res?.id || res?.data?.id;
                if (userId) {
                  const resp = await UserAPI.createCloudUsers([userId], {
                    [String(userId)]: payload.password,
                  });
                  const d = resp?.data || resp || {};
                  const fail = d.failCount || 0;
                  if (fail === 0) {
                    ElMessage.success("创建成功！");
                  } else {
                    ElMessage.error("创建失败，请联系管理员！");
                  }
                } else {
                  ElMessage.error("创建 cloud 账号失败：未获取到新用户 ID");
                }
              }
            } catch {
              ElMessage.error("创建 cloud 账号时发生错误，请联系管理员");
            }
            handleCloseDialog();
            handleResetQuery();
          })
          .finally(() => (loading.value = false));
      }
    }
  });
}, 1000);

/**
 * 检查是否删除当前登录用户
 * @param singleId 单个删除的用户ID
 * @param selectedIds 批量删除的用户ID数组
 * @param currentUserInfo 当前用户信息
 * @returns 是否包含当前用户
 */
function isDeletingCurrentUser(
  singleId?: number,
  selectedIds: number[] = [],
  currentUserInfo?: any
): boolean {
  if (!currentUserInfo?.userId) return false;

  // 单个删除检查
  if (singleId && singleId.toString() === currentUserInfo.userId) {
    return true;
  }

  // 批量删除检查
  if (!singleId && selectedIds.length > 0) {
    return selectedIds.map(String).includes(currentUserInfo.userId);
  }

  return false;
}

/**
 * 删除用户
 *
 * @param id  用户ID
 */
function handleDelete(id?: number) {
  const userIds = [id || selectIds.value].join(",");
  if (!userIds) {
    ElMessage.warning("请勾选删除项");
    return;
  }

  // 安全检查：防止删除当前登录用户
  const currentUserInfo = userStore.userInfo;
  if (isDeletingCurrentUser(id, selectIds.value, currentUserInfo)) {
    ElMessage.error("不能删除当前登录用户");
    return;
  }

  ElMessageBox.confirm("确认删除用户?", "警告", {
    confirmButtonText: "确定",
    cancelButtonText: "取消",
    type: "warning",
  }).then(
    () => {
      loading.value = true;
      UserAPI.deleteByIds(userIds)
        .then((resp: any) => {
          const data = resp?.data || resp || {};
          // 先显示本地删除成功提示
          ElMessage.success("删除成功");
          // 若后端返回 cloud 删除结果，则展示详细结果
          const cloudResults = data.cloudResults || [];
          if (cloudResults.length > 0) {
            const successes = cloudResults.filter((r: any) => r.success);
            const fails = cloudResults.filter((r: any) => !r.success);
            if (fails.length === 0) {
              ElMessage.success(`成功删除${successes.length}个cloud用户！`);
            } else {
              // 构建失败详情文本并弹窗展示
              const lines = fails.map((f: any) => `邮箱: ${f.email || ""} -> ${f.msg || "error"}`);
              ElMessageBox.alert(
                `云端删除失败 ${fails.length} 条：\n` + lines.join("\n"),
                "云端删除结果",
                {
                  type: "warning",
                  confirmButtonText: "确定",
                  showClose: true,
                  dangerouslyUseHTMLString: false,
                }
              );
            }
          }
          handleResetQuery();
        })
        .finally(() => (loading.value = false));
    },
    () => {
      ElMessage.info("已取消删除");
    }
  );
}

// 创建 Seafile cloud 用户（为选中用户）
async function handleCreateCloudUser() {
  if (!selectIds.value || selectIds.value.length === 0) {
    ElMessage.warning("请先勾选需要创建 cloud 用户的用户行");
    return;
  }
  loading.value = true;
  try {
    // 收集每个选中用户对应的密码（从表单中尝试读取，不存在则询问）
    const pwdMap: Record<string, string> = {};
    const ids: Array<string | number> = [];
    for (const id of selectIds.value) {
      ids.push(id);
      try {
        const u = await UserAPI.getFormData(String(id));
        const email = u.email;
        if (!email) {
          ElMessage.warning(`用户 ${u.username || id} 未配置邮箱，跳过`);
          continue;
        }
        let password = (u as any).password || "";
        if (!password) {
          try {
            const { value } = await ElMessageBox.prompt(
              `请输入用户 ${u.username || email} 的密码（用于同步到 Seafile）`,
              "输入密码",
              { inputType: "password", confirmButtonText: "确定", cancelButtonText: "取消" }
            );
            password = value;
          } catch {
            ElMessage.info("已取消该用户的创建");
            continue;
          }
        }
        pwdMap[String(id)] = password;
      } catch (e: any) {
        ElMessage.error(`获取用户信息失败：ID=${id} ${e?.message || e}`);
      }
    }

    if (Object.keys(pwdMap).length === 0) {
      ElMessage.warning("未收集到任何用户密码，操作已取消");
      return;
    }

    // 调用后端代理接口进行统一创建，避免浏览器 CORS
    const resp = await UserAPI.createCloudUsers(ids, pwdMap);
    const data = resp?.data || resp || {};
    const fail = data.failCount || 0;
    // 仅显示通用提示，避免泄露过多细节
    if (fail === 0) {
      ElMessage.success("创建成功！");
    } else {
      ElMessage.error("创建失败，或者用户已经创建！请联系管理员！");
    }
  } finally {
    loading.value = false;
    fetchData();
  }
}

// 打开导入弹窗
function handleOpenImportDialog() {
  importDialogVisible.value = true;
}

// 导出用户
function handleExport() {
  UserAPI.export(queryParams).then((response: any) => {
    const fileData = response.data;
    const fileName = decodeURI(response.headers["content-disposition"].split(";")[1].split("=")[1]);
    const fileType =
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;charset=utf-8";

    const blob = new Blob([fileData], { type: fileType });
    const downloadUrl = window.URL.createObjectURL(blob);

    const downloadLink = document.createElement("a");
    downloadLink.href = downloadUrl;
    downloadLink.download = fileName;

    document.body.appendChild(downloadLink);
    downloadLink.click();

    document.body.removeChild(downloadLink);
    window.URL.revokeObjectURL(downloadUrl);
  });
}

onMounted(() => {
  handleQuery();
});
</script>
