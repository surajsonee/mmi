import utils from './utils';

/*-----------------------------------------------
|                  Swiper
-----------------------------------------------*/
const swiperInit = () => {
  const Selector = {
    DATA_SWIPER : '[data-swiper]',
    DATA_ZANIM_TIMELINE: '[data-zanim-timeline]',
    IMG: 'img',
    SWIPER_NAV: '.swiper-nav',
    SWIPER_BUTTON_NEXT: '.swiper-button-next',
    SWIPER_BUTTON_PREV: '.swiper-button-prev',
    
  };
  const DATA_KEY = {
    SWIPER: 'swiper'
  };
  const Events = {
    SLIDE_CHANGE: 'slideChange'
  };

  const swipers = document.querySelectorAll(Selector.DATA_SWIPER);

  swipers.forEach((swiper) => {
    const options = utils.getData(swiper, DATA_KEY.SWIPER);
    const thumbsOptions = options.thumb;
    let thumbsInit;
    if (thumbsOptions) {
      const thumbImages = swiper.querySelectorAll(Selector.IMG);
      let slides = '';
      thumbImages.forEach((img) => {
        slides += `
          <div class='swiper-slide '>
            <img class='img-fluid rounded mt-1' src=${img.src} alt=''/>
          </div>
        `;
      });

      const thumbs = document.createElement('div');
      thumbs.setAttribute('class', 'swiper-container thumb');
      thumbs.innerHTML = `<div class='swiper-wrapper'>${slides}</div>`;

      if (thumbsOptions.parent) {
        const parent = document.querySelector(thumbsOptions.parent);
        parent.parentNode.appendChild(thumbs);
      } else {
        swiper.parentNode.appendChild(thumbs);
      }

      thumbsInit = new window.Swiper(thumbs, thumbsOptions);
    }

    const swiperNav = swiper.querySelector(Selector.SWIPER_NAV);
    const newSwiper = new window.Swiper(swiper, {
      ...options,
      navigation: {
        nextEl: swiperNav?.querySelector(Selector.SWIPER_BUTTON_NEXT),
        prevEl: swiperNav?.querySelector(Selector.SWIPER_BUTTON_PREV),
      },
      thumbs: {
        swiper: thumbsInit,
      },
    });


    //- zanimation effect start
    if(swiper){
      newSwiper.on(Events.SLIDE_CHANGE, function () {
        const timelineElements = swiper.querySelectorAll(Selector.DATA_ZANIM_TIMELINE);
        timelineElements.forEach( el => {     
          window.zanimation(el,animation => {
            setTimeout(() => {
              animation.play();
            }, 1200);
          });
        })
      });
    }
    //- zanimation effect end
   
  });

};

export default swiperInit;
