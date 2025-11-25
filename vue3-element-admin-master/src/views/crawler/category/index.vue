<template>
  <div class="app-container">
    <!-- 搜索区域 -->
    <div v-hasPerm="'pc:category:query'" class="search-container">
      <el-form ref="queryFormRef" :model="queryParams" :inline="true">
        <el-form-item label="关键字" prop="keywords">
          <el-input
            v-model="queryParams.keywords"
            placeholder="类目名/类目ID"
            clearable
            @keyup.enter="handleQuery"
          />
        </el-form-item>

        <el-form-item label="类目站点" prop="site">
          <el-select
            v-model="queryParams.site"
            placeholder="请选择站点"
            clearable
            style="width: 200px"
          >
            <el-option v-for="s in siteOptions" :key="s" :label="s" :value="s"></el-option>
          </el-select>
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
            v-hasPerm="'pc:category:add'"
            type="success"
            icon="plus"
            @click="handleAddClick()"
          >
            新增
          </el-button>
          <el-button
            v-hasPerm="'pc:category:delete'"
            type="danger"
            :disabled="ids.length === 0"
            icon="delete"
            @click="handleDelete()"
          >
            删除
          </el-button>
        </div>
      </div>

      <el-table
        v-loading="loading"
        highlight-current-row
        :data="tableData"
        border
        class="data-table__content"
        @selection-change="handleSelectionChange"
      >
        <el-table-column type="selection" width="55" align="center" />
        <el-table-column label="类目名" prop="name" />
        <el-table-column label="类目ID" prop="category_id" />
        <el-table-column label="类目站点" prop="site" />
        <el-table-column label="类目归类" prop="category_type" />
        <el-table-column label="状态" prop="status">
          <template #default="scope">
            <el-tag :type="scope.row.status === 1 ? 'success' : 'info'">
              {{ scope.row.status === 1 ? "正常" : "禁用" }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column fixed="right" label="操作" align="center" width="260">
          <template #default="scope">
            <el-button
              v-hasPerm="'pc:category:dk'"
              type="info"
              link
              size="small"
              @click.stop="handleViewData(scope.row)"
            >
              数据查看
            </el-button>
            <el-button
              v-hasPerm="'pc:category:edit'"
              type="primary"
              link
              size="small"
              icon="edit"
              @click.stop="handleEditClick(scope.row.id)"
            >
              编辑
            </el-button>
            <el-button
              v-hasPerm="'pc:category:delete'"
              type="danger"
              link
              size="small"
              icon="delete"
              @click.stop="handleDelete(scope.row.id)"
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

    <!-- 新增/编辑 弹窗 -->
    <el-dialog
      v-model="dialog.visible"
      :title="dialog.title"
      width="600px"
      @close="handleCloseDialog"
    >
      <el-form ref="dataFormRef" :model="formData" :rules="computedRules" label-width="120px">
        <el-form-item label="类目名" prop="name">
          <el-input v-model="formData.name" placeholder="请输入类目名" />
        </el-form-item>
        <el-form-item label="类目ID" prop="category_id">
          <el-input v-model="formData.category_id" placeholder="请输入类目ID" />
        </el-form-item>
        <el-form-item label="类目站点" prop="site">
          <el-input v-model="formData.site" placeholder="请输入站点" />
        </el-form-item>
        <el-form-item label="类目归类" prop="category_type">
          <el-input v-model="formData.category_type" placeholder="请输入归类" />
        </el-form-item>
        <el-form-item label="状态">
          <el-radio-group v-model="formData.status">
            <el-radio :value="1">正常</el-radio>
            <el-radio :value="0">禁用</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>

      <template #footer>
        <div class="dialog-footer">
          <el-button type="primary" @click="handleSubmitClick">确 定</el-button>
          <el-button @click="handleCloseDialog">取 消</el-button>
        </div>
      </template>
    </el-dialog>

    <!-- 数据查看 弹窗（含时间选择器） -->
    <el-dialog
      v-model="viewDialog.visible"
      title="数据查看"
      width="480px"
      @close="() => (viewDialog.visible = false)"
    >
      <el-form label-width="120px">
        <el-form-item label="选择日期">
          <el-date-picker
            v-model="viewDialog.time"
            type="date"
            placeholder="选择日期"
            style="width: 100%"
            format="YYYY-MM-DD"
            value-format="YYYY-MM-DD"
            @change="onDateChanged"
          />
        </el-form-item>
        <el-form-item v-if="viewDialog.needCloudPassword" label="输入 cloud 密码">
          <el-input
            v-model="viewDialog.cloudPassword"
            placeholder="请输入 cloud 密码以刷新后端缓存"
            show-password
            style="width: 100%"
          />
          <div style="margin-top: 8px; text-align: right">
            <el-button size="small" type="primary" @click="refreshCloudPasswordAndRetry">
              刷新并重试
            </el-button>
          </div>
        </el-form-item>
        <el-form-item label="可选时间">
          <el-table :data="timesList" size="small" stripe style="width: 100%">
            <el-table-column prop="index" label="序号" width="60" />
            <el-table-column prop="name" label="时间" />
            <el-table-column label="操作" width="160">
              <template #default="{ row }">
                <el-button
                  type="text"
                  size="small"
                  :disabled="!row.viewUrl"
                  @click="viewTime(row.viewUrl)"
                >
                  查看
                </el-button>
                <el-button
                  type="text"
                  size="small"
                  :disabled="!row.name"
                  @click="downloadTime(row.name)"
                >
                  下载
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="dialog-footer">
          <el-button type="primary" @click="onViewConfirm">确定</el-button>
          <el-button @click="() => (viewDialog.visible = false)">取消</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
defineOptions({ name: "CrawlerCategory", inheritAttrs: false });

import { ref, reactive, computed, onMounted } from "vue";
import { useUserStoreHook } from "@/store";
import request from "@/utils/request";
import {
  CategoryAPI,
  UserAPI,
  type CategoryPageQuery,
  type CategoryVO,
  type CategoryForm,
} from "@/backend";

const queryFormRef = ref();
const dataFormRef = ref();

const loading = ref(false);
const ids = ref<number[]>([]);
const total = ref(0);

const queryParams = reactive<CategoryPageQuery>({
  pageNum: 1,
  pageSize: 10,
  keywords: "",
  site: "",
});

const siteOptions = ref<string[]>([]);

const tableData = ref<CategoryVO[]>([]);

const dialog = reactive({ title: "", visible: false });
const viewDialog = reactive({
  visible: false,
  time: null as null | string,
  currentCategory: null as any,
  // inline cloud password flow
  needCloudPassword: false,
  cloudPassword: "",
  pendingDownloadName: null as string | null,
});

const timesList = ref<
  {
    index: number;
    name: string;
    viewUrl?: string | null;
    downloadUrl?: string | null;
  }[]
>([]);
const allTimes = ref<string[]>([]);
const allTimesDates = ref<string[]>([]);
const timesChecking = ref(false);

const formData = reactive<CategoryForm>({ status: 1 });

const computedRules = computed(() => ({
  name: [{ required: true, message: "类目名不能为空", trigger: "blur" }],
  category_id: [{ required: true, message: "类目ID不能为空", trigger: "blur" }],
}));

/**
 * 判断后端返回是否表示需要 cloud 密码（兼容多种字段/消息形式）
 */
function isNeedCloud(status: number | undefined, data: any) {
  try {
    const needCloudFlag =
      data && ((data.data && data.data.needCloudPassword) || data.needCloudPassword);
    const msg = (data && (data.msg || data.error_msg || data.error || "")) + "";
    const match = /未找到缓存|needCloudPassword|need cloud password|need cloud/i.test(msg);
    return status === 401 || !!needCloudFlag || match;
  } catch (e) {
    console.warn(e);
    return false;
  }
}

function fetchData() {
  loading.value = true;
  // include selected site in queryParams (server supports 'site')
  CategoryAPI.getPage(queryParams)
    .then((data) => {
      // 适配后端返回 { total, list } 或 直接数组
      if (Array.isArray(data)) {
        tableData.value = data;
        total.value = data.length;
      } else if (data && typeof data === "object") {
        tableData.value = data.list || data;
        total.value =
          data.total || (Array.isArray(data.list) ? data.list.length : tableData.value.length);
      } else {
        tableData.value = [];
        total.value = 0;
      }
    })
    .finally(() => (loading.value = false));
}

async function fetchSites() {
  try {
    const res = await request.get("/crawler/category/sites", {
      headers: { Authorization: "no-auth" },
    });
    if (Array.isArray(res)) {
      siteOptions.value = res;
    }
  } catch (e) {
    console.warn("fetchSites failed", e);
  }
}

function handleQuery() {
  queryParams.pageNum = 1;
  try {
    // trim keywords to avoid accidental 空格导致无匹配
    if (typeof queryParams.keywords === "string") {
      queryParams.keywords = queryParams.keywords.trim();
    }
  } catch {
    // ignore
  }
  fetchData();
}

function handleResetQuery() {
  queryFormRef.value.resetFields();
  queryParams.pageNum = 1;
  fetchData();
}

function handleSelectionChange(selection: any) {
  ids.value = selection.map((item: any) => item.id);
}

function handleAddClick() {
  dialog.visible = true;
  dialog.title = "新增类目";
  Object.assign(formData, {
    id: undefined,
    name: "",
    category_id: "",
    site: "",
    category_type: "",
    status: 1,
  });
}

function handleEditClick(id: string) {
  dialog.visible = true;
  dialog.title = "修改类目";
  CategoryAPI.getFormData(String(id)).then((data) => Object.assign(formData, data));
}

function handleSubmitClick() {
  dataFormRef.value.validate((isValid: boolean) => {
    if (isValid) {
      loading.value = true;
      const id = (formData as any).id;
      if (id) {
        CategoryAPI.update(String(id), formData)
          .then(() => {
            ElMessage.success("修改成功");
            handleCloseDialog();
            fetchData();
          })
          .finally(() => (loading.value = false));
      } else {
        CategoryAPI.create(formData)
          .then(() => {
            ElMessage.success("新增成功");
            handleCloseDialog();
            fetchData();
          })
          .finally(() => (loading.value = false));
      }
    }
  });
}

function handleDelete(id?: number) {
  const idsStr = id ? String(id) : ids.value.join(",");
  if (!idsStr) {
    ElMessage.warning("请勾选删除项");
    return;
  }
  ElMessageBox.confirm("确认删除已选中的数据项?", "警告", {
    confirmButtonText: "确定",
    cancelButtonText: "取消",
    type: "warning",
  })
    .then(() => {
      loading.value = true;
      CategoryAPI.deleteByIds(idsStr)
        .then(() => {
          ElMessage.success("删除成功");
          handleResetQuery();
        })
        .finally(() => (loading.value = false));
    })
    .catch(() => {
      ElMessage.info("已取消删除");
    });
}

function handleCloseDialog() {
  dialog.visible = false;
  dataFormRef.value.resetFields();
  dataFormRef.value.clearValidate();
}

async function handleViewData(row: any) {
  viewDialog.visible = true;
  viewDialog.time = null;
  viewDialog.currentCategory = row || null;
  timesList.value = [];

  // 先询问后端当前是否已缓存 Seafile 用户 token（后端字段名为 seafileCached）
  try {
    const profile: any = await UserAPI.getProfile();
    const cached = !!(
      profile &&
      (profile.seafileCached || (profile.data && profile.data.seafileCached))
    );
    if (cached) {
      viewDialog.needCloudPassword = false;
      if (row && row.id) {
        await loadTimes(String(row.id));
      }
    } else {
      // 未缓存：显示内嵌密码输入，用户可在此填写并点击“刷新并重试”按钮
      viewDialog.needCloudPassword = true;
      viewDialog.cloudPassword = "";
      viewDialog.pendingDownloadName = null;
      ElMessage.info("未找到缓存的 Seafile token，请在弹窗中输入 cloud 密码并点击刷新以继续");
    }
  } catch (err) {
    console.warn(err);
    // 若获取 profile 失败，也显示密码输入以便用户尝试刷新
    viewDialog.needCloudPassword = true;
    viewDialog.cloudPassword = "";
    viewDialog.pendingDownloadName = null;
    ElMessage.info("无法查询缓存状态，请输入 cloud 密码并点击刷新以继续");
  }
}

async function loadTimes(id: string) {
  try {
    timesChecking.value = true;
    const res = await CategoryAPI.getTimes(id);
    allTimes.value = res && res.all ? res.all : [];
    // 计算 allTimes 对应的 YYYY-MM-DD 格式，供日期选择器匹配使用
    allTimesDates.value = allTimes.value.map((n) => {
      if (/^\d{8}$/.test(n)) return `${n.slice(0, 4)}-${n.slice(4, 6)}-${n.slice(6, 8)}`;
      if (/^\d{6}$/.test(n)) return `20${n.slice(0, 2)}-${n.slice(2, 4)}-${n.slice(4, 6)}`;
      return n;
    });

    // 优化策略：先取按时间排序的前 3 个候选并发检查，若有候选返回 404 则从后续候选补上，直到收集到 3 条或耗尽。
    const display: {
      index: number;
      name: string;
      viewUrl?: string | null;
      downloadUrl?: string | null;
    }[] = [];

    const maxDisplay = 3;
    let nextIdx = 0; // 指向下一个未被检查的 allTimes 元素

    // 统一的检查单项函数：返回 true 表示该候选可展示并已加入 display；
    // 返回 false 表示不可展示（通常为 404），调用者可决定是否拿下一个候选继续检查；
    // 若遇到需要 cloud 密码或其它致命错误，会抛出异常以中断流程。
    const checkOne = async (cand: string) => {
      try {
        const chk = await CategoryAPI.checkFile(id, cand);
        if (chk && chk.exists) {
          // 保护性检查：仅在未满时加入（并发场景避免超过 maxDisplay）
          if (display.length < maxDisplay) {
            display.push({
              index: display.length + 1,
              name: cand,
              viewUrl: (chk as any).viewUrl || null,
              downloadUrl: (chk as any).downloadUrl || null,
            });
          }
          return true;
        }
        return false;
      } catch (err: any) {
        const resp = err && (err.response || err);
        const status = resp && resp.status;
        const data = resp && resp.data;
        if (isNeedCloud(status, data)) {
          // 需要 cloud 密码，切换到内嵌输入流程并中断上层
          viewDialog.needCloudPassword = true;
          viewDialog.cloudPassword = "";
          viewDialog.pendingDownloadName = null;
          ElMessage.info("请输入 cloud 密码（弹窗内嵌），填写后点击'刷新并重试'。若不填写可取消。");
          // 抛出特殊错误以便上层停止并保持 timesChecking=false
          const e = new Error("needCloud");
          (e as any).code = "needCloud";
          throw e;
        }
        // 非 404 的其它错误视为致命错误，提示并中断
        if (status && status !== 404) {
          let msg = "检查文件可用性失败";
          try {
            msg = (data && (data.msg || data.error_msg)) || err.message || msg;
          } catch (ex) {
            console.warn(ex);
          }
          ElMessage.error(msg);
          const e = new Error("fatal");
          (e as any).code = "fatal";
          throw e;
        }
        // 404 -> 文件不存在，返回 false 以便调用方继续取下一个
        return false;
      }
    };

    // 并发 worker：从队列中拉取下一个候选并执行检查；若失败（404）且还有后续候选则递归继续；
    // 若遇到 needCloud 或 fatal 错误，会抛出并由外层捕获。
    const worker = async (initialCand: string) => {
      let cand = initialCand;
      while (cand && display.length < maxDisplay) {
        const ok = await checkOne(cand);
        if (ok) return;
        // 未找到（404），取下一个候选继续检查
        if (nextIdx < allTimes.value.length) {
          cand = allTimes.value[nextIdx++];
        } else {
          // 没有候选可补，结束
          return;
        }
      }
    };

    try {
      // 启动最多 maxDisplay 个并发 worker，从 allTimes 顺序取候选
      const workers: Promise<any>[] = [];
      for (let i = 0; i < maxDisplay && nextIdx < allTimes.value.length; i++) {
        const cand = allTimes.value[nextIdx++];
        workers.push(worker(cand));
      }
      // 等待所有 worker 完成（或被 needCloud/fatal 中断）
      await Promise.all(workers);
    } catch (e: any) {
      // 若是 needCloud，上层会根据 viewDialog.needCloudPassword 做处理；将 timesChecking 置 false 并返回
      if (e && (e.code === "needCloud" || (e.message && e.message === "needCloud"))) {
        timesChecking.value = false;
        return;
      }
      // fatal 或其它异常已在 checkOne 中提示，直接结束
      timesChecking.value = false;
      return;
    }

    timesList.value = display;
  } catch (e: any) {
    // 尝试从不同位置读取后端返回的结构化错误
    const resp = e && (e.response || e);
    const status = resp && resp.status;
    const data = resp && resp.data;
    // 当后端告知需要 cloudPassword 时（401 + needCloudPassword: true 或消息文本）
    if (isNeedCloud(status, data)) {
      // 提示用户输入 cloud 密码并调用 UserAPI.updateProfile 以触发后端缓存 token
      // 切换到内嵌输入流程：在 Data View 弹窗显示密码输入框并等待用户刷新
      viewDialog.needCloudPassword = true;
      viewDialog.cloudPassword = "";
      viewDialog.pendingDownloadName = null;
      ElMessage.info("请输入 cloud 密码（弹窗内嵌），填写后点击'刷新并重试'。若不填写可关闭弹窗。");
      return;
    }

    // 其他错误（如 404/502）给出友好提示
    let msg = "查询时间失败";
    try {
      if (data && data.data && data.data.msg) {
        msg = data.data.msg;
      } else if (data && data.msg) {
        msg = data.msg;
      } else if (e && e.message) {
        msg = e.message;
      }
    } catch (ex) {
      console.warn(ex);
    }
    ElMessage.error(msg);
  } finally {
    timesChecking.value = false;
  }
}

function onViewConfirm() {
  const v = viewDialog.time || "";
  ElMessage.info(`已选择日期：${v}`);
  viewDialog.visible = false;
}

async function selectTime(name: string) {
  // 点击“查看”：向后端请求文件流（带 Authorization），前端接收 Blob 并在新标签页中打开
  if (!viewDialog.currentCategory || !viewDialog.currentCategory.id) {
    ElMessage.error("缺少当前类目信息");
    return;
  }
  const id = String(viewDialog.currentCategory.id);
  try {
    // 优先使用 checkFile 获取后端返回的外链（downloadUrl/viewUrl）
    const chk = await CategoryAPI.checkFile(id, name);
    if (chk && chk.exists && chk.downloadUrl) {
      // 后端直接返回下载外链，打开该外链即可
      window.open(String(chk.downloadUrl), "_blank");
      return;
    }
    // 若返回结构不符合预期或未包含 downloadUrl，则尝试退回到 downloadFile（兼容旧实现）
    const blob = await CategoryAPI.downloadFile(id, name);
    const url = window.URL.createObjectURL(blob as any);
    window.open(url, "_blank");
    setTimeout(() => window.URL.revokeObjectURL(url), 60 * 1000);
    return;
  } catch (err: any) {
    const resp = err && (err.response || err);
    const status = resp && resp.status;
    const data = resp && resp.data;
    if (status === 404 || (data && data.error_msg && data.error_msg.includes("File not found"))) {
      ElMessage.error("文件不存在");
    } else if (isNeedCloud(status, data)) {
      // 需要 cloud 密码，提示并刷新 token 后重试
      try {
        // 切换到内嵌输入流程：在 Data View 弹窗显示密码输入框并等待用户刷新
        viewDialog.needCloudPassword = true;
        viewDialog.cloudPassword = "";
        viewDialog.pendingDownloadName = name;
        ElMessage.info("请输入 cloud 密码（弹窗内嵌），填写后点击'刷新并重试'以继续下载。");
        return;
      } catch (ex) {
        console.warn(ex);
        ElMessage.info("已取消");
      }
    } else {
      let msg = "下载失败";
      try {
        msg = (data && (data.msg || data.error_msg)) || err.message || msg;
      } catch (ex) {
        console.warn(ex);
      }
      ElMessage.error(msg);
    }
  }
}

function viewTime(url: string | null | undefined) {
  if (!url) {
    ElMessage.error("无可用外链");
    return;
  }
  window.open(String(url), "_blank");
}

async function downloadTime(name: string) {
  // delegate to selectTime which handles download + auth refresh
  await selectTime(name);
}

async function onDateChanged(val: string | null) {
  // 当用户使用日期选择器时，尝试在 allTimesDates 中找到对应记录并只显示该项
  if (!val) {
    // 恢复默认最新三条（重新走一次 loadTimes 以保证可查看性检查）
    if (viewDialog.currentCategory && viewDialog.currentCategory.id) {
      await loadTimes(String(viewDialog.currentCategory.id));
    }
    return;
  }
  const idx = allTimesDates.value ? allTimesDates.value.findIndex((d) => d === val) : -1;
  if (idx >= 0) {
    const folderName = allTimes.value[idx];
    try {
      const chk = await CategoryAPI.checkFile(String(viewDialog.currentCategory.id), folderName);
      if (chk && chk.exists) {
        timesList.value = [
          {
            index: 1,
            name: folderName,
            viewUrl: chk.viewUrl || null,
            downloadUrl: chk.downloadUrl || null,
          },
        ];
      } else {
        timesList.value = [];
        ElMessage.warning("所选日期对应的文件不存在");
      }
    } catch (err) {
      console.warn(err);
      timesList.value = [];
      ElMessage.warning("检查文件失败");
    }
  } else {
    timesList.value = [];
    ElMessage.warning("未找到与所选日期匹配的时间记录");
  }
}

onMounted(() => {
  fetchSites();
  fetchData();
});

/**
 * 在数据查看弹窗内嵌的 cloudPassword 刷新并重试逻辑
 */
async function refreshCloudPasswordAndRetry() {
  if (!viewDialog.cloudPassword) {
    ElMessage.warning("请输入 cloud 密码后再刷新");
    return;
  }
  try {
    timesChecking.value = true;
    await UserAPI.updateProfile({ cloudPassword: viewDialog.cloudPassword });
    ElMessage.success("已刷新 cloud token，正在重试...");
    // 清理内嵌状态
    viewDialog.needCloudPassword = false;
    const pending = viewDialog.pendingDownloadName;
    viewDialog.pendingDownloadName = null;
    const catId = viewDialog.currentCategory && viewDialog.currentCategory.id;
    // 若有待下载的文件名则直接继续下载，否则刷新列表
    if (pending && catId) {
      await selectTime(pending);
    } else if (catId) {
      await loadTimes(String(catId));
    }
  } catch (err) {
    console.warn(err);
    ElMessage.error("刷新失败，请检查密码或联系管理员");
    try {
      timesChecking.value = true;
      await UserAPI.updateProfile({ cloudPassword: viewDialog.cloudPassword });
      ElMessage.success("已请求后端刷新 cloud token，正在验证状态...");

      // 主动拉取 profile 以验证后端是否已缓存 Seafile token
      try {
        const profile: any = await UserAPI.getProfile();
        const cached = !!(
          profile &&
          (profile.seafileCached || (profile.data && profile.data.seafileCached))
        );
        // 如果后端确认缓存，则更新本地 store 并继续流程
        if (cached) {
          try {
            const userStore = useUserStoreHook();
            // 更新 Pinia 中的 seafileCached（并写入 Storage）
            (userStore as any).seafileCached = cached;
          } catch (e) {
            console.warn("更新 userStore seafileCached 失败", e);
          }

          viewDialog.needCloudPassword = false;
          const pending = viewDialog.pendingDownloadName;
          viewDialog.pendingDownloadName = null;
          viewDialog.cloudPassword = "";
          const catId = viewDialog.currentCategory && viewDialog.currentCategory.id;
          if (pending && catId) {
            await selectTime(pending);
          } else if (catId) {
            await loadTimes(String(catId));
          }
        } else {
          // 未被后端缓存，提示用户
          ElMessage.error("后端未能缓存 Seafile token，请确认密码是否正确或联系管理员");
        }
      } catch (e) {
        console.warn("验证 profile 失败", e);
        ElMessage.error("刷新后验证失败，请稍后重试");
      }
    } catch (err) {
      console.warn(err);
      ElMessage.error("刷新失败，请检查密码或联系管理员");
    } finally {
      timesChecking.value = false;
      viewDialog.cloudPassword = "";
    }
  }
}
</script>

<style scoped>
.app-container {
  padding: 16px;
}
.search-container {
  margin-bottom: 12px;
}
.data-table__toolbar {
  display: flex;
  justify-content: space-between;
  margin-bottom: 8px;
}
.data-table__toolbar--actions {
  display: flex;
  gap: 8px;
}
</style>
