<template>
  <div class="app-container">
    <!-- 搜索区域 -->
    <div class="search-container">
      <el-form ref="queryFormRef" :model="queryParams" :inline="true">
        <el-form-item label="关键字" prop="keywords">
          <el-input v-model="queryParams.keywords" placeholder="节点" @keyup.enter="handleQuery" />
        </el-form-item>

        <el-form-item class="search-buttons">
          <el-button class="filter-item" type="primary" icon="search" @click="handleQuery">
            搜索
          </el-button>
          <el-button icon="refresh" @click="handleResetQuery">重置</el-button>
        </el-form-item>
      </el-form>
    </div>

    <el-card shadow="hover" class="data-table">
      <div class="data-table__toolbar">
        <div class="data-table__toolbar--actions">
          <el-button
            v-hasPerm="['pc:conf:add']"
            type="success"
            icon="plus"
            @click="handleOpenDialog()"
          >
            新增
          </el-button>
          <el-button
            v-hasPerm="['pc:conf:delete']"
            type="danger"
            :disabled="selectIds.length === 0"
            icon="delete"
            @click="handleDelete()"
          >
            删除
          </el-button>
        </div>
      </div>

      <el-table
        v-loading="loading"
        :data="list"
        row-key="id"
        class="data-table__content"
        @selection-change="handleSelectionChange"
      >
        <el-table-column type="selection" width="55" align="center" />
        <el-table-column prop="server_name" label="服务器名称" min-width="200" />
        <el-table-column prop="node" label="节点" width="200" />
        <el-table-column prop="ip" label="IP" width="160" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="scope">
            <el-tag v-if="scope.row.status" type="success">正常</el-tag>
            <el-tag v-else type="info">禁用</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="order_num" label="排序" width="100" />

        <el-table-column label="操作" fixed="right" align="left" width="220">
          <template #default="scope">
            <el-button
              v-hasPerm="['pc:conf:edit']"
              type="primary"
              link
              size="small"
              icon="edit"
              @click.stop="handleOpenDialog(undefined, scope.row.id)"
            >
              编辑
            </el-button>
            <el-button
              v-hasPerm="['pc:conf:delete']"
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

    <el-dialog
      v-model="dialog.visible"
      :title="dialog.title"
      width="600px"
      @closed="handleCloseDialog"
    >
      <el-form ref="formRef" :model="formData" :rules="rules" label-width="120px">
        <el-form-item label="服务器名称" prop="server_name">
          <el-input v-model="formData.server_name" placeholder="请输入服务器名称" />
        </el-form-item>
        <el-form-item label="节点" prop="node">
          <el-input v-model="formData.node" placeholder="请输入节点" />
        </el-form-item>
        <el-form-item label="IP" prop="ip">
          <el-input v-model="formData.ip" placeholder="请输入 IP 地址" />
        </el-form-item>
        <el-form-item label="排序" prop="order_num">
          <el-input-number
            v-model="formData.order_num"
            controls-position="right"
            style="width: 100px"
            :min="0"
          />
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
          <el-button type="primary" @click="handleSubmit">确 定</el-button>
          <el-button @click="handleCloseDialog">取 消</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
defineOptions({ name: "CrawlerConf", inheritAttrs: false });

import { ref, reactive, onMounted } from "vue";
import { CrawlerAPI, type CrawlerConfVO, type CrawlerConfForm } from "@/backend";

const queryFormRef = ref();
const formRef = ref();

const loading = ref(false);
const selectIds = ref<number[]>([]);
const total = ref(0);
const queryParams = reactive<any>({ pageNum: 1, pageSize: 10, keywords: "" });

const dialog = reactive({ title: "", visible: false });
const list = ref<CrawlerConfVO[]>([]);

const formData = reactive<CrawlerConfForm>({ status: 1, order_num: 1 });

const rules = reactive({
  server_name: [{ required: true, message: "服务器名称不能为空", trigger: "blur" }],
  node: [{ required: true, message: "节点不能为空", trigger: "blur" }],
  ip: [{ required: true, message: "IP 不能为空", trigger: "blur" }],
});

function fetchData() {
  loading.value = true;
  // 支持后端返回数组或 { total, list }
  CrawlerAPI.getList({
    pageNum: queryParams.pageNum,
    pageSize: queryParams.pageSize,
    keywords: queryParams.keywords,
  })
    .then((data: any) => {
      if (Array.isArray(data)) {
        list.value = data;
        total.value = data.length;
      } else if (data && typeof data === "object") {
        list.value = data.list || data;
        total.value =
          data.total || (Array.isArray(data.list) ? data.list.length : list.value.length);
      } else {
        list.value = [];
        total.value = 0;
      }
    })
    .finally(() => (loading.value = false));
}

function handleResetQuery() {
  queryFormRef.value.resetFields();
  queryParams.pageNum = 1;
  fetchData();
}

function handleSelectionChange(selection: any) {
  selectIds.value = selection.map((item: any) => item.id);
}

async function handleOpenDialog(parentId?: string | number, id?: string | number) {
  dialog.visible = true;
  if (id) {
    dialog.title = "修改节点";
    CrawlerAPI.getFormData(String(id)).then((data) => Object.assign(formData, data));
  } else {
    dialog.title = "新增节点";
    formData.server_name = "";
    formData.node = "";
    formData.ip = "";
    formData.status = 1;
    formData.order_num = 1;
  }
}

function handleSubmit() {
  formRef.value.validate((valid: any) => {
    if (valid) {
      loading.value = true;
      const id = (formData as any).id;
      if (id) {
        CrawlerAPI.update(String(id), formData)
          .then(() => {
            ElMessage.success("修改成功");
            handleCloseDialog();
            handleQuery();
          })
          .finally(() => (loading.value = false));
      } else {
        CrawlerAPI.create(formData)
          .then(() => {
            ElMessage.success("新增成功");
            handleCloseDialog();
            handleQuery();
          })
          .finally(() => (loading.value = false));
      }
    }
  });
}

function handleDelete(id?: number) {
  const ids = id ? String(id) : selectIds.value.join(",");
  if (!ids) {
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
      CrawlerAPI.deleteByIds(ids)
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
  resetForm();
}

function resetForm() {
  formRef.value.resetFields();
  formRef.value.clearValidate();
  (formData as any).id = undefined;
  formData.server_name = "";
  formData.node = "";
  formData.ip = "";
  formData.status = 1;
  formData.order_num = 1;
}

function handleQuery() {
  queryParams.pageNum = 1;
  fetchData();
}

onMounted(() => {
  fetchData();
});
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
