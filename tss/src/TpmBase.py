import platform
from .TpmTypes import *
from .TpmDevice import *
from .Crypt import Crypto
from tpmstream.io.binary import Binary
from tpmstream.io.pretty import Pretty
from tpmstream.spec.commands.commands import Command
from tpmstream.spec.commands.responses import Response

Owner = TPM_HANDLE(TPM_RH.OWNER)
Endorsement = TPM_HANDLE(TPM_RH.ENDORSEMENT)

NullSymDef = TPMT_SYM_DEF(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL)

def parse_command(buffer=b"\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x44\x00\x00"):
    events = Binary.marshal(tpm_type=Command, buffer=buffer, command_code=None)
    pretty = Pretty.unmarshal(events=events)

    for line in pretty:
         print(line)

def parse_response(buffer=b"\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x44\x00\x00", command_code=None):
    events = Binary.marshal(tpm_type=Response, buffer=buffer, command_code=command_code)
    pretty = Pretty.unmarshal(events=events)

    for line in pretty:
         print(line)

class Session:
    def __init__(self,
        sessionType = TPM_SESSION_TYPE.PASSWORD,
        sessionHandle = None,
        nonceTpm = None,
        nonceCaller=None,
        salt = None,
        authHash = None,
        sessionAttributes=TPMA_SESSION.continueSession
    ):
        self.SessIn = TPMS_AUTH_COMMAND(sessionHandle, nonceCaller, sessionAttributes)
        self.SessOut = TPMS_AUTH_RESPONSE(nonceTpm, sessionAttributes)

    @staticmethod
    def Pw(authValue = None): # Session
        s = Session()
        s.SessIn.sessionHandle = TPM_HANDLE(TPM_RH.RS_PW)
        s.SessIn.nonce = None
        s.SessIn.sessionAttributes = TPMA_SESSION.continueSession
        s.SessIn.hmac = authValue
        s.SessOut.sessionAttributes = TPMA_SESSION.continueSession
        return s

    def StartSession(self, keyHandle=None, keyPublic=None, bind=None, encDecAlg=None):
        digestsz = Crypt.digestSize(authhash)
        nonceCaller = Crypt.randomBytes(digestsz)



# class Session

NullPwSession = Session.Pw()


class TpmBase(object):
    def __init__(self, useSimulator = False, host = '127.0.0.1', port = 2321):
        if useSimulator:
            self.__device = TpmTcpDevice(host, port)
        elif platform.system() == 'Windows':
            self.__device = TpmTbsDevice()
        else:
            self.__device = TpmLinuxDevice()
        self.__lastResponseCode = TPM_RC.SUCCESS
        self.__lastError = None    # TpmError
        self.enableExceptions(True)
        self.__sessions = None
        #self.__cmdBuf = None
        self.__cmdCode = 0

    def connect(self):
        try:
            self.__device.connect()
        except Exception as e:
            if isinstance(self.__device, TpmLinuxDevice):
                # It is possible that a user mode TRM from tpm2-tools is running
                self.__device = TpmTcpDevice('127.0.0.1', 2323, True)
                self.__device.connect()
            else:
                raise

    def close(self):
        if self.__device:
            self.__device.close()
            self.__device = None

    def poweron(self):
        platReq = bytesFromList([0, 0, 0, int(TPM_TCP_PROTOCOL.SignalPowerOn)])
        self.__platSocket.send(platReq)

    def poweroff(self):
        platReq = bytesFromList([0, 0, 0, int(TPM_TCP_PROTOCOL.SignalPowerOff)])
        self.__platSocket.send(platReq)

    def reset(self):
        platReq = bytesFromList([0, 0, 0, int(TPM_TCP_PROTOCOL.SignalReset)])
        self.__platSocket.send(platReq)

    @property
    def lastResponseCode(self): 
        return self.__lastResponseCode

    @property
    def lastError(self):
        return self.__lastError

    def allowErrors(self):
        """ For the next TPM command invocation, errors will not cause an exception to be thrown
            (use _lastCommandSucceeded or _getLastResponseCode() to check for an error)
        Returns:
            This object (to allow modifier chaining)
        """
        self.__errorsAllowed = True
        return self

    def enableExceptions(self, enable = True):
        """ When exceptions are enabled, errors reported by the TPM or occurred in the TSS (e.g. during 
            an attempt to communicate with the TPM) will result in throwing an exception of TpmError type.
            It will still be possible to use _lastCommandSucceeded(), _getLastResponseCode() methods and
            lastError property to check for an error after the exception is intercepted.
            Note that in contrast to allowErrors() this method affects all subsequent commands. 
        """
        self.__exceptionsEnabled = enable
        self.__errorsAllowed = not enable
    
    def withSession(self, sess):
        """ Specifies a single session handle to use with the next command
        Args:
            sess Session handle
        Returns:
            This object (to allow modifier chaining)
        """
        self.__sessions = [sess]
        return self

    def withSessions(self, *sessions):
        """ Specifies a single session handle to use with the next command
        Args:
            sessions Up to 3 session handles
        Returns:
            This object (to allow modifier chaining)
        """
        print('withSessions: ' + str(NewPython))
        self.__sessions = list(sessions)
        return self

    @staticmethod
    def __isCommMediumError(respCode):
        """ Checks whether the response code is generated by the TSS.JS (i.e. is an extension to the TPM 2.0 spec)
        Args:
            code Response code returned by TSS.JS
        Returns:
            true if the response code was generated in the communication channel between the app and the TPM
        """
        return (respCode & 0xFFFF0000) == 0x80280000

    @staticmethod
    def __cleanResponseCode(rawResponse):
        if TpmBase.__isCommMediumError(rawResponse):
            return TPM_RC(rawResponse)

        if rawResponse & TPM_RC.RC_FMT1:
            mask = TPM_RC.RC_FMT1 | 0x3F
        else:
            mask = TPM_RC.RC_WARN | TPM_RC.RC_VER1 | 0x7F
        return TPM_RC(rawResponse & mask)

    def dispatchCommand(self,
        cmdCode,                # TPM_CC
        req,                    # ReqStructure derived class
    ):
        handles = req.getHandles()
        numAuthHandles = req.numAuthHandles()
        cmdBuf = TpmBuffer()

        self.__cmdCode = cmdCode
        self.__cmdTag = TPM_ST.SESSIONS if numAuthHandles > 0 else TPM_ST.NO_SESSIONS

        cmdBuf.writeShort(self.__cmdTag)
        cmdBuf.writeInt(0)  # to be filled in later
        cmdBuf.writeInt(cmdCode)

        if handles and len(handles) > 0:
            for h in handles:
                if not h:
                    cmdBuf.writeInt(TPM_RH.NULL)
                else:
                    h.toTpm(cmdBuf)

        if numAuthHandles > 0:
            if not self.__sessions:
                self.__sessions = [None] * numAuthHandles
            elif len(self.__sessions) < numAuthHandles:
                self.sessions = self.__sessions + [None] * (numAuthHandles - len(self.__sessions))

            for i in range(numAuthHandles):
                if not self.__sessions[i]:
                    self.__sessions[i] = Session.Pw()

            # We do not know the size of the authorization area yet.
            # Remember the place to marshal it, ...
            authSizePos = cmdBuf.curPos
            # ... and marshal a placeholder 0 value for now.
            cmdBuf.writeInt(0)

            for sess in self.__sessions:
                sess.SessIn.toTpm(cmdBuf)

            #authSize = cmdBuf.curPos - authSizePos - 4
            #cmdBuf.buffer[authSizePos : authSizePos + 4] = intToTpm(authSize, 4)
            cmdBuf.writeNumAtPos(cmdBuf.curPos - authSizePos - 4, authSizePos)

        self.__sessions = None
        self.__lastError = None

        # Marshal command parameters
        req.toTpm(cmdBuf)

        # Fill in command buffer size in the command header
        cmdBuf.writeNumAtPos(cmdBuf.curPos, 2)
        cmdBuf.trim()
        rc = TPM_RC.RETRY
        print(cmdBuf.buffer.hex())
        parse_command(cmdBuf.buffer)
        while rc == TPM_RC.RETRY:
            respBuf = self.__device.dispatchCommand(cmdBuf.buffer)
            rc = intFromTpm(respBuf, 6, 4)
        print(respBuf.hex())
        parse_response(respBuf, cmdCode)
        return TpmBuffer(respBuf)
    # __dispatchCommand()

    @staticmethod
    def __generateErrorResponse(rc):
        respBuf = TpmBuffer()
        respBuf.writeShort(TPM_ST.NO_SESSIONS)
        respBuf.writeInt(10)
        respBuf.writeInt(rc)
        return respBuf

    def __generateError(self, respCode, errMsg, errorsAllowed):
        self.__lastResponseCode = respCode
        self.__lastError = TpmError(respCode, self.__cmdCode, errMsg)
        if self.__exceptionsEnabled and not errorsAllowed:
            raise(self.__lastError)
        return None

    def processResponse(self, respBuf, RespType = None):
        """ Returns unmarshaled response data structure or None in case of error """

        if self.lastError:
            return None

        errorsAllowed = self.__errorsAllowed
        self.__errorsAllowed = not self.__exceptionsEnabled

        if respBuf.size < 10:
            self.__generateError(TPM_RC.TSS_RESP_BUF_TOO_SHORT,
                    'Response buffer is too short: ' + str(len(respBuf)), errorsAllowed)
            return None

        if respBuf.curPos != 0:
            raise(Exception('Response buffer reading position is not properly initialized'))

        tag = respBuf.readShort()       # TPM_ST
        respSize = respBuf.readInt()
        rc = respBuf.readInt()          # TPM_RC

        self.__lastResponseCode = TpmBase.__cleanResponseCode(rc)

        if (rc == TPM_RC.SUCCESS and tag != int(self.__cmdTag)
        or rc != TPM_RC.SUCCESS and tag != int(TPM_ST.NO_SESSIONS)):
            self.__generateError(TPM_RC.TSS_RESP_BUF_INVALID_SESSION_TAG,
                                 'Invalid session tag in the response buffer')
            return None

        if self.__lastResponseCode != TPM_RC.SUCCESS:
            self.__generateError(self.lastResponseCode, 'Command {' + str(self.__cmdCode) + 
                    '} failed with error {' + str(self.lastResponseCode) + '}', errorsAllowed)
            return None

        if not RespType:
            return None     # No values are expected to be returned by the TPM

        resp = RespType()

        # Get the handles
        if resp.numHandles() > 0:
            resp.setHandle(TPM_HANDLE(respBuf.readInt()))

        # If a response session is present, response buffer contains a field
        # specifying the size of response parameters
        respParamsSize = respBuf.readInt() if tag == TPM_ST.SESSIONS else respBuf.size - respBuf.curPos

        paramStart = respBuf.curPos
        resp.initFromTpm(respBuf)

        if respParamsSize != respBuf.curPos - paramStart:
            return self.generateError(TPM_RC.TSS_RESP_BUF_INVALID_SIZE, 
                        'Inconsistent TPM response params size: expected ${exp}, actual ${act}'
                            .format(exp = respParamsSize, act = respBuf.curPos - paramStart),
                        errorsAllowed)
        return resp
    # processResponse()

# class TpmBase
