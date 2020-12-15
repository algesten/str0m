//
const rtc1 = new RTCPeerConnection();
const rtc2 = new RTCPeerConnection();
rtc1.id = '1';
rtc2.id = '2';


const setup = async (rtc, other) => {
  rtc.addEventListener("iceconnectionstatechange", (e) =>
    console.log(rtc.id, "ice conn:", rtc.iceConnectionState)
  );
  rtc.addEventListener("connectionstatechange", (e) =>
    console.log(rtc.id, "conn:", rtc.connectionState)
  );
  rtc.addEventListener("negotiationneeded", () => negotiate(rtc, other));
};

let negotiating = {};

const applyOffer = async (sdp, rtc) => {
  console.log(rtc.id, 'apply remote description');

  await rtc.setRemoteDescription({
    type: "offer",
    sdp,
  });

  const answer = await rtc.createAnswer();
  return answer;
}

const negotiate = async (rtc, other) => {
  if (negotiating[rtc.id]) {
    return;
  }
  negotiating[rtc.id] = true;
  console.log(rtc.id, "createOffer");
  const offer = await rtc.createOffer();
  console.log(rtc.id, "setLocalDescription");
  await rtc.setLocalDescription(offer);
  const { sdp } = offer;
  console.log(rtc.id, "SEND ", sdp);
  const res = await applyOffer(sdp, other);
  console.log(rtc.id, "RECV ", res.sdp);
  console.log(rtc.id, "setRemoteDescription");
  await rtc.setRemoteDescription({
    type: "answer",
    sdp: res.sdp,
  });
  negotiating[rtc.id] = false;
};

const selfTestVideo = async () => {
  console.log("selfTestVideo");
  const stream = await navigator.mediaDevices.getUserMedia({ video: true });

  rtc1.addTransceiver(stream.getTracks()[0], {
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

rtc2.ontrack = (ev) => {
  console.log(rtc2.id, ev.track);
};

setup(rtc1, rtc2);
setup(rtc2, rtc1);
negotiate(rtc1, rtc2);
