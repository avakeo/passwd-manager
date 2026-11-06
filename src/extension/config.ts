// 拡張機能の設定。ここは仮の値（リポジトリには実際の接続先を書かない）。
// ビルド（scripts/build-extension.ts）が、Git の管理外の config/extension.local.json の値で、出力の config.js を書き換える。
// webOrigin は「Web ページを開く」の開く先（2026-11-05 追記、W-09）。null なら、ボタンを出さない
export const CONFIG: { apiOrigin: string; webOrigin: string | null; discordClientId: string } = {
  apiOrigin: 'https://pw-api.example.com',
  webOrigin: null,
  discordClientId: '000000000000000000',
};
