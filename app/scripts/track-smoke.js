const response = await fetch("http://localhost:3000/v/track", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-site-key": process.env.SITE_KEY ?? ""
  },
  body: JSON.stringify({
    video_id: process.env.VIDEO_ID ?? "video_smoke_test",
    percent: 25,
    event_source_url: process.env.EVENT_SOURCE_URL ?? "https://example.com/video"
  })
});

const responseBody = await response.text();
console.log("status", response.status);
console.log("body", responseBody);
