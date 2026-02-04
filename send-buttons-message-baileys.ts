import { proto } from 'baileys'

import {
  checkJid,
  generateImageMessage,
  generateVideoMessage,
  socket,
  type SendMessageInput,
} from '..'

import { checkTrial } from '../middleware/check-trial'

type SendActionButtonsMessageInput = SendMessageInput & {
  body?: string
  title?: string
  footer?: string
  buttons: {
    type: 'url' | 'copy' | 'call' | 'reply'
    displayText: string
    id: string
    copyCode?: string
    url?: string
    phoneNumber?: string
  }[]
  image?: string
  video?: string
}

type SendCarouselMessageInput = SendMessageInput & {
  message?: string
  carousel: {
    text: string
    image: string
    buttons: {
      id: string
      displayText: string
      type: 'url' | 'copy' | 'call' | 'reply'
      url?: string
      phoneNumber?: string
      copyCode?: string
    }[]
  }[]
}

type SendListMessageInput = SendMessageInput & {
  buttonText: string
  title?: string
  description: string
  footer?: string
  sections: {
    title?: string
    rows: {
      title: string
      description?: string
      rowId: string
    }[]
  }[]
}

export async function sendActionButtonsMessage({
  jid: originalJid,
  body,
  title,
  footer,
  buttons,
  image,
  video,
}: SendActionButtonsMessageInput) {
  const jid = await checkJid(originalJid)
  if (socket) {
    await socket.relayMessage(
      jid,
      {
        interactiveMessage: {
          body: body ? { text: await checkTrial(body) } : undefined,
          header:
            title || image || video
              ? {
                  title,
                  imageMessage: image
                    ? await generateImageMessage(image)
                    : undefined,
                  videoMessage: video
                    ? await generateVideoMessage(video)
                    : undefined,
                  hasMediaAttachment: !!(image || video),
                }
              : undefined,
          footer: footer ? { text: footer } : undefined,
          nativeFlowMessage: {
            buttons: buttons.map(button => ({
              name:
                button.type === 'reply' ? 'quick_reply' : `cta_${button.type}`,
              buttonParamsJson: JSON.stringify({
                id: button.id,
                display_text: button.displayText,
                disabled: false,
                copy_code: button.copyCode,
                url: button.url,
                phone_number: button.phoneNumber,
              }),
            })),
          },
        },
      },
      {
        additionalNodes: [
          {
            tag: 'biz',
            attrs: {},
            content: [
              {
                tag: 'interactive',
                attrs: {
                  v: '1',
                  type: 'native_flow',
                },
                content: [
                  {
                    tag: 'native_flow',
                    attrs: {
                      v: '2',
                      name: 'mixed',
                    },
                  },
                ],
              },
            ],
          },
        ],
      },
    )
  }
}

export async function sendCarouselMessage({
  jid: originalJid,
  message,
  carousel,
}: SendCarouselMessageInput) {
  if (socket) {
    const jid = await checkJid(originalJid)
    const imageMessages: (proto.Message.IImageMessage | undefined | null)[] = []
    for (const card of carousel) {
      const imageMessage = await generateImageMessage(card.image)
      imageMessages.push(imageMessage)
    }
    const cards = await Promise.all(
      carousel.map(async (card, index) => ({
        header: {
          imageMessage: imageMessages[index],
          hasMediaAttachment: true,
        },
        body: {
          text: await checkTrial(card.text),
        },
        nativeFlowMessage: {
          buttons: card.buttons.map(button => ({
            name:
              button.type === 'reply' ? 'quick_reply' : `cta_${button.type}`,
            buttonParamsJson: JSON.stringify({
              id: button.id,
              display_text: button.displayText,
              disabled: false,
              copy_code: button.copyCode,
              url: button.url,
              phone_number: button.phoneNumber,
            }),
          })),
        },
      })),
    )
    await socket.relayMessage(
      jid,
      {
        interactiveMessage: {
          body: {
            text: message ? await checkTrial(message) : undefined,
          },
          carouselMessage: {
            cards,
          },
        },
      },
      {
        additionalNodes: [
          {
            tag: 'biz',
            attrs: {},
            content: [
              {
                tag: 'interactive',
                attrs: {
                  v: '1',
                  type: 'native_flow',
                },
                content: [
                  {
                    tag: 'native_flow',
                    attrs: {
                      v: '2',
                      name: 'mixed',
                    },
                  },
                ],
              },
            ],
          },
        ],
      },
    )
  }
}

export async function sendListMessage({
  jid,
  buttonText,
  title,
  footer,
  description,
  sections,
}: SendListMessageInput) {
  if (socket) {
    await socket.relayMessage(
      jid,
      {
        listMessage: {
          title,
          description: description ? await checkTrial(description) : undefined,
          footerText: footer,
          buttonText,
          listType: proto.Message.ListMessage.ListType.SINGLE_SELECT,
          sections,
        },
      },
      {
        additionalNodes: [
          {
            tag: 'biz',
            attrs: {},
            content: [
              {
                tag: 'list',
                attrs: {
                  v: '2',
                  type: 'product_list',
                },
              },
            ],
          },
        ],
      },
    )
  }
}
