

/* -------------------------------------------------------------------------- */
/*                                  Preloader                                 */
/* -------------------------------------------------------------------------- */


const preloaderInit = () => {
  const bodyElement = document.querySelector('body');
  window.imagesLoaded( bodyElement, ()=> {
      const preloader = document.querySelector('.preloader');
      preloader?.classList.add('loaded');
      setTimeout(() => { 
        preloader?.remove();
      }, 800);
  });

};

export default preloaderInit;