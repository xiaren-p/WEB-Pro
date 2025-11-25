<template>
  <div class="external-redirect">
    <div v-if="useIframe" class="iframe-wrapper">
      <iframe :src="link" frameborder="0" />
    </div>
    <div v-else class="opening">正在打开外部链接...</div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, computed } from "vue";
import { useRoute, useRouter } from "vue-router";

const route = useRoute();
const router = useRouter();

const link = computed(() => (route.meta?.link as string) || "");
// 可切换为 iframe 内嵌或新开页，这里默认新开标签
const useIframe = false;

onMounted(() => {
  const url = link.value;
  if (!url) {
    // 无链接，回到首页
    router.replace("/");
    return;
  }
  if (useIframe) return; // 采用 iframe 展示
  // 默认新开标签并回退
  try {
    window.open(url, "_blank", "noopener,noreferrer");
  } catch {
    /* ignore */
  }
  // 回退上一页或首页
  if (history.length > 1) {
    router.back();
  } else {
    router.replace("/");
  }
});
</script>

<style scoped>
.external-redirect {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
}
.iframe-wrapper {
  width: 100%;
  height: 100%;
}
.iframe-wrapper iframe {
  width: 100%;
  height: 100%;
}
</style>
