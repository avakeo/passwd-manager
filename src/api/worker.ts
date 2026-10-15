// Workers の入口。本番はこのアプリだけを使う（テスト用の認証や差し込み口はない）。

import { createApp } from './app.ts';

export default createApp();
