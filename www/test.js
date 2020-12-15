//
const rtc = new RTCPeerConnection();

// rtc.createDataChannel("my-pony1");
// rtc.createDataChannel("my-pony2");

// rtc.addTransceiver("video", {
//   direction: "sendonly",
//   sendEncodings: [
//     { maxBitrate: 40000, rid: 'hi' },
//     { maxBitrate: 10000, rid: 'lo' },
//   ],
// });

const setup = async () => {
  rtc.addEventListener("iceconnectionstatechange", (e) =>
    console.log("ice conn:", rtc.iceConnectionState)
  );
  rtc.addEventListener("connectionstatechange", (e) =>
    console.log("conn:", rtc.connectionState)
  );
  rtc.addEventListener("negotiationneeded", negotiate);
  await negotiate();
};

const postSdp = async (sdp) => {
  const req = { room_id: 'hej', sdp };
  console.log("POST", req.sdp);
  const res = await fetch(`/join`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(req),
  }).then((r) => r.json());
  console.log("POST RECV", res.sdp);
  return res;
};

let negotiating = false;

const negotiate = async () => {
  if (negotiating) {
    return;
  }
  negotiating = true;
  console.log("createOffer");
  const offer = await rtc.createOffer();
  console.log("setLocalDescription");
  await rtc.setLocalDescription(offer);
  const { sdp } = offer;
  console.log("postSdp");
  const res = await postSdp(sdp);
  console.log("setRemoteDescription");
  await rtc.setRemoteDescription({
    type: "answer",
    sdp: res.sdp,
  });
  negotiating = false;
};

const addMic = async () => {
  console.log("addMic");
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });

  rtc.addTransceiver(stream.getTracks()[0], {
    direction: "sendonly"
  });

};

const addVideo = async () => {
  console.log("addVideo");
  const stream = await navigator.mediaDevices.getUserMedia({ video: true });

  rtc.addTransceiver(stream.getTracks()[0], {
    streams: [stream],
    direction: "sendonly",
  });

  // const simulcastParams = [
  //   { rid: 'hi', active: true, maxBitrate: 40000 },
  //   { rid: 'lo', active: true, maxBitrate: 10000, scaleResolutionDownBy: 2 },
  // ];

  // rtc.addTransceiver(stream.getTracks()[0], {
  //   direction: "sendonly",
  //   sendEncodings: simulcastParams,
  // });

  // const sender = rtc.getSenders()[0];
  // const params = sender.getParameters();

  // if (Object.keys(params).length == 0) {
  //   params.encoding = simulcastParams;
  //   sender.setParameters(params);
  // }

};

setup().catch(console.error);
