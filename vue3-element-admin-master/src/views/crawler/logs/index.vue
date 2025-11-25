<template>
  <div class="app-container">
    <!-- 搜索区域 -->
    <div class="search-container">
      <el-form ref="queryFormRef" :model="queryParams" :inline="true">
        <el-form-item prop="keywords" label="关键字">
          <el-input
            v-model="queryParams.keywords"
            placeholder="日志内容"
            clearable
            @keyup.enter="handleQuery"
          />
        </el-form-item>

        <el-form-item prop="createTime" label="日志时间">
          <el-date-picker
            v-model="queryParams.createTime"
            :editable="false"
            type="daterange"
            range-separator="~"
            start-placeholder="开始时间"
            end-placeholder="截止时间"
            value-format="YYYY-MM-DD"
            style="width: 200px"
          />
        </el-form-item>

        <el-form-item class="search-buttons">
          <el-button type="primary" icon="search" @click="handleQuery">搜索</el-button>
          <el-button icon="refresh" @click="handleResetQuery">重置</el-button>
        </el-form-item>
      </el-form>
    </div>

    <el-card shadow="hover" class="data-table">
      <el-table
        v-loading="loading"
        :data="pageData"
        highlight-current-row
        border
        class="data-table__content"
      >
        <el-table-column label="日志时间" prop="createTime" width="180" />
        <el-table-column label="日志级别" prop="level" width="120" />
        <el-table-column label="日志内容" prop="content" min-width="300" />
        <el-table-column label="模块耗时(ms)" prop="executionTime" width="140" />
      </el-table>

      <pagination
        v-if="total > 0"
        v-model:total="total"
        v-model:page="queryParams.pageNum"
        v-model:limit="queryParams.pageSize"
        @pagination="fetchData"
      />
    </el-card>
  </div>
</template>

<script setup lang="ts">
defineOptions({ name: "CrawlerLogs", inheritAttrs: false });

import { ref, reactive, onMounted } from "vue";
import request from "@/utils/request";

const queryFormRef = ref();

const loading = ref(false);
const total = ref(0);

const queryParams = reactive({
  pageNum: 1,
  pageSize: 10,
  keywords: "",
  createTime: ["", ""],
});

const pageData = ref<any[]>([]);

function fetchData() {
  loading.value = true;
  // 使用开放接口，不强制携带 Authorization
  request
    .get("/crawler/logs/page", { params: queryParams, headers: { Authorization: "no-auth" } })
    .then((data: any) => {
      if (Array.isArray(data)) {
        pageData.value = data;
        total.value = data.length;
      } else if (data && typeof data === "object") {
        pageData.value = data.list || [];
        total.value = data.total || (Array.isArray(data.list) ? data.list.length : pageData.value.length);
      } else {
        pageData.value = [];
        total.value = 0;
      }
    })
    .catch((e) => {
      console.warn(e);
    })
    .finally(() => {
      loading.value = false;
    });
}

function handleQuery() {
  queryParams.pageNum = 1;
  fetchData();
}

function handleResetQuery() {
  try {
    queryFormRef.value.resetFields();
  } catch {
    // ignore
  }
  queryParams.pageNum = 1;
  queryParams.createTime = ["", ""];
  fetchData();
}

onMounted(() => {
  handleQuery();
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
