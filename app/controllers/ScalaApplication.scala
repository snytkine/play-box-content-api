package controllers

import java.io.File
import java.nio.charset.StandardCharsets
import java.security.{MessageDigest, SecureRandom}

import play.api.libs.json.{JsError, JsSuccess, Json}
import play.api.libs.ws.{WSClient, WSResponse}
import play.api.mvc._
import play.twirl.api.Html

import scala.concurrent.{Future, Promise}
import javax.inject._

import play.api.Configuration
import play.api.cache.CacheApi

import scala.concurrent.ExecutionContext

@javax.inject.Singleton
class ScalaApplication @Inject()(wsClient: WSClient,
                                 cacheApi: CacheApi,
                                 config: Configuration)(implicit ec: ExecutionContext) extends Controller {
  private val logger = org.slf4j.LoggerFactory.getLogger("application")

  import scala.concurrent.duration._

  val file = new File(".", "README")
  val clientId = config.getString("client.id").get
  val clientSecret = config.getString("client.secret").get
  val boxLogin = config.getString("client.login").get
  val redirectUri = "http://localhost:9000/authorize"

  private val random = new SecureRandom()
  private val encoder = java.util.Base64.getUrlEncoder


  def index = Action.async { implicit request =>
    val nonce = generateNonce(boxLogin)
    val key = generateKey(nonce)

    // NOTE: the cache MUST be distributed here to keep track of the nonce
    cacheApi.set(key, nonce, 5.minutes)
    val future = wsClient.url("https://account.box.com/api/oauth2/authorize")
      .withQueryString(
        "response_type" -> "code",
        "client_id" -> clientId,
        "redirect_uri" -> redirectUri,
        "state" -> nonce,
        "box_login" -> boxLogin
      ).get()

    future.map { result =>
      Ok(Html(result.body))
    }
  }

  def authorize = Action.async { implicit request =>
    request.getQueryString("error").map { error =>
      val errorDescription = request.getQueryString("error_description")
      Future.successful {
        Unauthorized(errorDescription.getOrElse("Unknown"))
      }
    }.getOrElse {
      val code = request.getQueryString("code").get
      val incomingNonce = request.getQueryString("state").get
      val key = generateKey(incomingNonce)
      cacheApi.get[String](key) match {
        case Some(n) =>
          logger.info(s"found nonce $n for key $key")
          cacheApi.remove(key)
          validateAuthorization(code)
        case None =>
          Future.successful(Unauthorized("unknown"))
      }
    }
  }

  def validateAuthorization(code: String) = {
    wsClient.url("https://api.box.com/oauth2/token").post(
      Map(
        "grant_type" -> Seq("authorization_code"),
        "code" -> Seq(code),
        "client_id" -> Seq(clientId),
        "client_secret" -> Seq(clientSecret)
      )
    ).flatMap { result =>
      result.status match {
        case (200) =>
          val json = result.json
          (json \ "access_token").validate[String] match {
            case JsSuccess(accessToken, _) =>
              uploadFile(accessToken, file).map { response =>
                Ok(response.json)
              }.recover {
                case e: Exception =>
                  GatewayTimeout(e.toString)
              }

            case JsError(errors) =>
              // json \ "error"
              Future.successful {
                Unauthorized("Invalid user credentials")
              }
          }

        case other =>
          logger.error(s"Unexpected error $other")
          logger.error(s"${Json.stringify(result.json)}")
          Future.successful {
            BadRequest("Unexpected error")
          }
      }
    }
  }

  def uploadFile(accessToken: String, file: File): Future[WSResponse] = {
    import com.ning.http.client.{Response => AHCResponse}
    import com.ning.http.client.multipart._
    import play.api.libs.ws.ning.NingWSResponse
    import com.ning.http.client.AsyncCompletionHandler

    val filePart: FilePart = new FilePart("filename", file)

    val url = "https://upload.box.com/api/2.0/files/content"
    val json = Json.obj("name" -> filePart.getFile.getName, "parent" -> Json.obj("id" -> "0"))

    val ningClient = wsClient.underlying[com.ning.http.client.AsyncHttpClient]
    val builder = new com.ning.http.client.RequestBuilder("POST")

    builder.setUrl(url)
    builder.addBodyPart(filePart)
    builder.addBodyPart(new StringPart("attributes", Json.stringify(json)))
    builder.setHeader("Authorization", s"Bearer $accessToken")
    builder.setHeader("Content-Type", "multipart/form-data")

    var result = Promise[NingWSResponse]()
    ningClient.executeRequest(builder.build(), new AsyncCompletionHandler[AHCResponse]() {
      override def onCompleted(achResponse: AHCResponse) = {
        result.success(NingWSResponse(achResponse))
        achResponse
      }

      override def onThrowable(t: Throwable) = {
        result.failure(t)
      }
    })

    result.future
  }

  private def generateKey(nonce: String) = {
    val key = s"$clientId-$nonce-$redirectUri"
    val md = MessageDigest.getInstance("SHA-256")
    md.update(key.getBytes())
    encoder.encodeToString(md.digest())
  }

  private def generateNonce(login: String): String = {
    val buffer = new Array[Byte](16) // 128 bit random
    random.nextBytes(buffer)
    val u = encoder.encodeToString(login.getBytes(StandardCharsets.UTF_8))
    encoder.encodeToString(buffer) + "-" + u
  }

}
