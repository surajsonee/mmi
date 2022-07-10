/* -------------------------------------------------------------------------- 
|                                 bg player                                  
--------------------------------------------------------------------------- */
import utils from "./utils";

const bgPlayerInit = () => {
  const Selector = {
    DATA_YOUTUBE_EMBED: '[data-youtube-embed]',
    YT_VIDEO: '.yt-video',
  };

  const DATA_KEY = {
    YOUTUBE_EMBED: 'youtube-embed',
  };

  const ClassName = {
    LOADED: 'loaded'
  };

  const Events = {
    SCROLL: 'scroll',
    LOADING: 'loading',
    DOM_CONTENT_LOADED: 'DOMContentLoaded'
  };

  const youtubeEmbedElements = document.querySelectorAll(Selector.DATA_YOUTUBE_EMBED);
  const loadVideo = () => {
    function setupPlayer() { 

      window.YT.ready(function() { 
        youtubeEmbedElements.forEach(youtubeEmbedElement => {
    
          const userOptions = utils.getData(youtubeEmbedElement, DATA_KEY.YOUTUBE_EMBED);
          const defaultOptions = { 
            videoId : 'hLpy-DRuiz0',
            startSeconds : 1,
            endSeconds : 50
          };
          const options = window._.merge(defaultOptions, userOptions);
    
          const youTubePlayer =  () => {
            // eslint-disable-next-line
            new YT.Player(youtubeEmbedElement, { 
              videoId: options.videoId, 
              playerVars: {
                autoplay: 1,
                disablekb: 1,
                controls: 0, 
                modestbranding: 1,// Hide the Youtube Logo
                loop: 1, 
                fs: 0, 
                enablejsapi: 0, 
                start: options?.startSeconds,
                end: options?.endSeconds,
                
              },
              events: {
                onReady: e => {
                  e.target.mute();
                  e.target.playVideo(); 
                },
                onStateChange:  e =>  {
                  if (e.data === window.YT.PlayerState.PLAYING) {
                    document.querySelectorAll(Selector.DATA_YOUTUBE_EMBED).forEach( embedElement => {
                      embedElement.classList.add(ClassName.LOADED);
                    })            
                  }

                  if (e.data === window.YT.PlayerState.PAUSED) {
                    e.target.playVideo();   
                  }
      
                  if (e.data === window.YT.PlayerState.ENDED) {
                    // Loop from starting point
                    e.target.seekTo(options.startSeconds);
                  }
                }
              }
            }); 
          };
    
          youTubePlayer();
        });
      });
    };


    const tag = document.createElement("script");
    tag.src = "https://www.youtube.com/iframe_api";
    const firstScriptTag = document.getElementsByTagName("script")[0];
    firstScriptTag.parentNode.insertBefore(tag, firstScriptTag);
    tag.onload = setupPlayer;

  }
  
  if (document.readyState !== Events.LOADING) {
    loadVideo();
  } 
  else {
    document.addEventListener(Events.DOM_CONTENT_LOADED, () =>  loadVideo() );
  }

  /* -------------------------------------------------------------------------- 
  |                                 Adjust BG Ratio                                
  --------------------------------------------------------------------------- */

  const adjustBackgroundRatio = () => {
    const ytElements = document.querySelectorAll(Selector.YT_VIDEO);
    ytElements.forEach( (ytEl)=>{
      
      const ytElement = ytEl;
      const width = ytElement.parentElement.offsetWidth+200;
      const height = (width*9)/16;
      const minHeight = ytElement.parentElement.offsetHeight+112;
      const minWidth = (minHeight*16)/9;

      ytElement.style.width = width+'px'
      ytElement.style.height = height+'px'
      ytElement.style.minHeight = minHeight+'px'
      ytElement.style.minWidth = minWidth+'px'

    })
  };
  adjustBackgroundRatio(); 
  document.addEventListener(Events.SCROLL, () => adjustBackgroundRatio() );


}
export default bgPlayerInit;

